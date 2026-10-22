import pkg/chronos
import pkg/questionable/results
import pkg/libp2p/[cid, protobuf/minprotobuf]
import std/sequtils
import pkg/promethei/chunker
import pkg/promethei/blocktype as bt
import pkg/promethei/manifest
import pkg/poseidon2

import pkg/promethei/slots
import pkg/promethei/merkletree
import pkg/promethei/indexingstrategy

import ../asynctest
import ./helpers
import ./examples

func verifiablePhysicalSize(prot: Manifest): NBytes =
  ## The verifiable dataset's physical size (protected leaves + all slot
  ## parity blocks at the protected block size); matches the layout binding
  ## enforced by Manifest.verify.
  NBytes(
    (prot.protectedBlocksCount + prot.numSlots * prot.parityBlocksPerSlot).int *
      prot.blockSize.int
  )

proc encodeDecode(manifest: Manifest): Manifest =
  let e = manifest.encode().tryGet()
  Manifest.decode(e).tryGet()

suite "Manifest":
  let
    manifest =
      Manifest.new(treeCid = Cid.example, blockSize = 1.MiBs, datasetSize = 100.MiBs)

    protectedManifest = Manifest.new(
      manifest = manifest,
      treeCid = Cid.example,
      datasetSize = 200.MiBs,
      eck = 2,
      ecM = 2,
      strategy = SteppedStrategy,
    )

    leaves = [
      0.toF.Poseidon2Hash, 1.toF.Poseidon2Hash, 2.toF.Poseidon2Hash, 3.toF.Poseidon2Hash
    ]

    slotLeavesCids = leaves.toSlotCids().tryGet

    tree = Poseidon2Tree.init(leaves).tryGet
    verifyCid = tree.root.tryGet.toVerifyCid().tryGet

    verifiableManifest = Manifest
      .new(
        manifest = protectedManifest,
        treeCid = protectedManifest.treeCid,
        datasetSize = verifiablePhysicalSize(protectedManifest),
        verifyRoot = verifyCid,
        slotRoots = slotLeavesCids,
      )
      .tryGet()

  test "Should encode/decode to/from base manifest":
    check:
      encodeDecode(manifest) == manifest

  test "Should encode/decode large manifest":
    let large = Manifest.new(
      treeCid = Cid.example,
      blockSize = (64 * 1024).NBytes,
      datasetSize = (5 * 1024).MiBs,
    )

    check:
      encodeDecode(large) == large

  test "Should encode/decode to/from protected manifest":
    check:
      encodeDecode(protectedManifest) == protectedManifest

  test "Should encode/decode to/from verifiable manifest":
    check:
      encodeDecode(verifiableManifest) == verifiableManifest

suite "Manifest - Attribute Inheritance":
  proc makeProtectedManifest(strategy: StrategyType): Manifest =
    Manifest.new(
      manifest = Manifest.new(
        treeCid = Cid.example,
        blockSize = 1.MiBs,
        datasetSize = 5.MiBs,
        filename = "example.png".some,
        mimetype = "image/png".some,
      ),
      treeCid = Cid.example,
      datasetSize = 10.MiBs,
      ecK = 1,
      ecM = 1,
      strategy = strategy,
    )

  test "Should preserve interleaving strategy for protected manifest in verifiable manifest":
    var verifiable = Manifest
      .new(
        manifest = makeProtectedManifest(SteppedStrategy),
        treeCid = Cid.example,
        datasetSize = 10.MiBs,
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    check verifiable.protectedStrategy == SteppedStrategy

    verifiable = Manifest
      .new(
        manifest = makeProtectedManifest(LinearStrategy),
        treeCid = Cid.example,
        datasetSize = 10.MiBs,
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    check verifiable.protectedStrategy == LinearStrategy

  test "Should preserve metadata for manifest in verifiable manifest":
    var verifiable = Manifest
      .new(
        manifest = makeProtectedManifest(SteppedStrategy),
        treeCid = Cid.example,
        datasetSize = 10.MiBs,
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    check verifiable.filename.isSome == true
    check !verifiable.filename == "example.png"
    check verifiable.mimetype.isSome == true
    check !verifiable.mimetype == "image/png"

  test "Can provide slot block iterator for verifiable manifest":
    let verifiable = Manifest
      .new(
        manifest = makeProtectedManifest(SteppedStrategy),
        treeCid = Cid.example,
        datasetSize = 10.MiBs,
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    let
      dataPerSlot = verifiable.dataBlocksPerSlot
      parityPerSlot = verifiable.parityBlocksPerSlot
      protectedCount = verifiable.protectedBlocksCount

    check:
      dataPerSlot == 5
      dataPerSlot + verifiable.numPadSlotBlocks == verifiable.numSlotBlocksTotal
      parityPerSlot ==
        verifiable.firstPassParityBlocks + verifiable.secondPassParityBlocks

    for slot in 0 ..< verifiable.numSlots:
      let iter = verifiable.getSlotIterator(slot).tryGet()
      var seen: seq[int]
      while not iter.finished:
        seen.add(iter.next())

      let
        dataPart = seen[0 ..< dataPerSlot]
        parityPart = seen[dataPerSlot .. ^1]
      check:
        dataPart.len == dataPerSlot
        dataPart.allIt(it < protectedCount)
        parityPart.len == parityPerSlot
        parityPart ==
          toSeq(
            protectedCount + slot * parityPerSlot ..<
              protectedCount + (slot + 1) * parityPerSlot
          )

  test "Slot iterator requires a verifiable manifest":
    let unprotected =
      Manifest.new(treeCid = Cid.example, blockSize = 1.MiBs, datasetSize = 10.MiBs)
    check:
      unprotected.getSlotIterator(0).isErr
      unprotected.getSlotIterator(0).error.msg == "Manifest is not protected"
      unprotected.getOriginalIterator().isErr
      unprotected.getOriginalIterator().error.msg == "Manifest is not protected"

    let protectedOnly = makeProtectedManifest(SteppedStrategy)
    check:
      protectedOnly.getSlotIterator(0).isErr
      protectedOnly.getSlotIterator(0).error.msg == "Manifest is not verifiable"

    # protected manifests expose the original data partition
    let orig = protectedOnly.getOriginalIterator().tryGet()
    var origSeen: seq[int]
    while not orig.finished:
      origSeen.add(orig.next())
    check origSeen == @[0, 1, 2, 3, 4]

  test "Verifiable manifest round-trip preserves version and protected view":
    let
      protected = makeProtectedManifest(SteppedStrategy)
      # production shape: the top level describes the ENLARGED verifiable
      # dataset, the protected view is carried in the verifiable section
      verifiableSize = (
        protected.blockSize.int * (
          protected.protectedBlocksCount +
          protected.numSlots * protected.parityBlocksPerSlot
        )
      ).NBytes
      verifiable = Manifest
        .new(
          manifest = protected,
          treeCid = Cid.example,
          datasetSize = verifiableSize,
          verifyRoot = Cid.example,
          slotRoots = @[Cid.example, Cid.example],
        )
        .tryGet()
      decoded = encodeDecode(verifiable)
    check:
      decoded.version == ManifestVersionV1
      decoded.cidVersion == protected.cidVersion
      decoded.innerK == InnerCodeK.int
      decoded.innerN == InnerCodeN.int
      decoded.treeCid == verifiable.treeCid
      decoded.datasetSize == verifiableSize
      decoded.blocksCount == verifiable.blocksCount
      decoded.protectedTreeCid == protected.treeCid
      decoded.protectedDatasetSize == protected.datasetSize

  test "Reject unsupported manifest version on decode":
    proc decodeWith(version: uint32): ?!Manifest =
      var header = initProtoBuffer()
      header.write(1, Cid.example.data.buffer)
      header.write(2, 1.MiBs.uint32)
      header.write(3, 100.MiBs.uint64)
      header.write(4, BlockCodec.uint32)
      header.write(5, Sha256HashCodec.uint32)
      header.write(6, version)
      header.write(10, CIDv1.uint32)
      header.finish()
      var pbNode = initProtoBuffer()
      pbNode.write(1, header)
      pbNode.finish()
      Manifest.decode(pbNode.buffer)

    # The identical header decodes with the supported version, so the
    # rejection below is the version check rather than a missing field.
    let manifest = decodeWith(ManifestVersionV1).tryGet
    check manifest.version == ManifestVersionV1

    check decodeWith(2'u32).isErr

  test "Verify uses the protected blocks count for verifiable manifests":
    # top-level datasetSize is the physical (enlarged) size; verify must
    # check the protected partition, not the top-level blocksCount
    let physical = Manifest
      .new(
        manifest = makeProtectedManifest(SteppedStrategy), # 10 protected blocks
        treeCid = Cid.example,
        datasetSize = verifiablePhysicalSize(makeProtectedManifest(SteppedStrategy)),
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    check physical.verify().isOk

    let broken = Manifest
      .new(
        manifest = Manifest.new(
          manifest = Manifest.new(
            treeCid = Cid.example, blockSize = 1.MiBs, datasetSize = 11.MiBs
          ),
          treeCid = Cid.example,
          datasetSize = 11.MiBs, # 11 blocks != steps*(ecK+ecM) = 22
          ecK = 1,
          ecM = 1,
          strategy = SteppedStrategy,
        ),
        treeCid = Cid.example,
        datasetSize = 11.MiBs,
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    check broken.verify().isErr
    check broken.verify().error.msg == "Broken manifest: wrong originalBlocksCount"

  test "Inner geometry derives from the layout version constant":
    let verifiable = Manifest
      .new(
        manifest = makeProtectedManifest(SteppedStrategy),
        treeCid = Cid.example,
        datasetSize = 10.MiBs,
        verifyRoot = Cid.example,
        slotRoots = @[Cid.example, Cid.example],
      )
      .tryGet()

    check:
      verifiable.innerK == InnerCodeK.int
      verifiable.innerN == InnerCodeN.int
      verifiable.rowShards ==
        verifiable.numBlockCells * verifiable.innerN div verifiable.innerK
      verifiable.colShards ==
        verifiable.numSlotBlocksTotal * verifiable.innerN div verifiable.innerK
      verifiable.firstPassParityBlocks ==
        (
          verifiable.numSlotBlocksTotal *
          (verifiable.rowShards - verifiable.numBlockCells) + verifiable.numBlockCells -
          1
        ) div verifiable.numBlockCells
      verifiable.parityBlocksPerSlot ==
        verifiable.firstPassParityBlocks + verifiable.secondPassParityBlocks

  test "Protected view exposes the protected root for repair addressing":
    let
      protected = makeProtectedManifest(SteppedStrategy)
      verifiable = Manifest
        .new(
          manifest = protected,
          treeCid = protected.treeCid,
          datasetSize = protected.datasetSize,
          verifyRoot = Cid.example,
          slotRoots = @[Cid.example, Cid.example],
        )
        .tryGet()
      view = verifiable.protectedView().tryGet()
    check:
      view.protected
      not view.verifiable
      view.treeCid == protected.treeCid
      view.datasetSize == protected.datasetSize
      makeProtectedManifest(SteppedStrategy).protectedView().isErr
