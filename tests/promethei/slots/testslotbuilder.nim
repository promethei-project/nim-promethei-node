import std/math
import std/sequtils
import std/importutils

import ../../asynctest

import pkg/chronos
import pkg/questionable/results
import pkg/kvstore
import pkg/taskpools
import pkg/promethei/blocktype as bt
import pkg/promethei/rng
import pkg/promethei/stores
import pkg/promethei/chunker
import pkg/promethei/merkletree
import pkg/promethei/manifest {.all.}
import pkg/promethei/utils
import pkg/promethei/utils/digest
import pkg/poseidon2
import pkg/poseidon2/io

import ./helpers
import ../helpers
import ../examples
import ../merkletree/helpers

import pkg/promethei/indexingstrategy {.all.}
import pkg/promethei/slots {.all.}
import pkg/promethei/erasure
import pkg/promethei/stores/repostore/operations

privateAccess(Poseidon2Builder) # enable access to private fields
privateAccess(Manifest) # enable access to private fields

const Strategy = LinearStrategy

proc newTestBuilderResult(
    store: RepoStore, manifest: Manifest, tp: Taskpool, cellSize: NBytes
): ?!Poseidon2Builder =
  Poseidon2Builder.new(
    store,
    store,
    Erasure.new(store, store, leoEncoderProvider, leoDecoderProvider, tp),
    manifest,
    cellSize = cellSize,
  )

proc newTestBuilder(
    store: RepoStore, manifest: Manifest, tp: Taskpool, cellSize: NBytes
): Poseidon2Builder =
  newTestBuilderResult(store, manifest, tp, cellSize).tryGet

suite "Slot builder":
  let
    blockSize = NBytes 1024
    cellSize = NBytes 64
    ecK = 3
    ecM = 2

    numSlots = ecK + ecM
    numDatasetBlocks = 8
    numTotalBlocks = calcEcBlocksCount(numDatasetBlocks, ecK, ecM)
      # total number of blocks in the dataset after
      # EC (should will match number of slots)
    originalDatasetSize = numDatasetBlocks * blockSize.int
    totalDatasetSize = numTotalBlocks * blockSize.int

    numSlotBlocks = numTotalBlocks div numSlots
    numBlockCells = (blockSize div cellSize).int # number of cells per block
    numSlotCells = numSlotBlocks * numBlockCells # number of uncorrected slot cells
    pow2SlotCells = nextPowerOfTwo(numSlotCells) # pow2 cells per slot
    numPadSlotBlocks = (pow2SlotCells div numBlockCells) - numSlotBlocks
      # pow2 blocks per slot

    numSlotBlocksTotal =
      # pad blocks per slot
      if numPadSlotBlocks > 0:
        numPadSlotBlocks + numSlotBlocks
      else:
        numSlotBlocks

    numBlocksTotal = numSlotBlocksTotal * numSlots
    parityPerSlot = 3 * numSlotBlocksTotal

    # Pads are all-1s bytes (explicit fill: no zero-init under -d:danger)
    emptyDigest = SpongeMerkle.digest(newSeqWith(blockSize.int, 0xFF'u8), cellSize.int)

  var
    datasetBlocks: seq[bt.Block]
    localStore: RepoStore
    manifest: Manifest
    protectedManifest: Manifest
    builder: Poseidon2Builder
    chunker: Chunker
    tp: Taskpool

  setup:
    tp = Taskpool.new(num_threads = 4)
    let
      repoDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()
      metaDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()

    localStore = RepoStore.new(repoDs, metaDs)
    chunker =
      RandomChunker.new(Rng.instance(), size = totalDatasetSize, chunkSize = blockSize)
    datasetBlocks = await chunker.createBlocks()

    (manifest, protectedManifest) = await createProtectedManifest(
      datasetBlocks, localStore, numDatasetBlocks, ecK, ecM, blockSize,
      originalDatasetSize, totalDatasetSize,
    )

  teardown:
    await localStore.close()
    tp.shutdown()

    # TODO: THIS IS A BUG IN asynctest, because it doesn't release the
    #       objects after the test is done, so we need to do it manually
    #
    # Need to reset all objects because otherwise they get
    # captured by the test runner closures, not good!
    reset(datasetBlocks)
    reset(localStore)
    reset(manifest)
    reset(protectedManifest)
    reset(builder)
    reset(chunker)

  test "Can only create builder with protected manifest":
    let unprotectedManifest = Manifest.new(
      treeCid = Cid.example,
      blockSize = blockSize.NBytes,
      datasetSize = originalDatasetSize.NBytes,
    )

    check:
      newTestBuilderResult(localStore, unprotectedManifest, tp, cellSize).isErr
      newTestBuilderResult(localStore, unprotectedManifest, tp, cellSize).error.msg ==
        "Manifest is not protected."

  test "Number of blocks must be devisable by number of slots":
    let mismatchManifest = Manifest.new(
      manifest = Manifest.new(
        treeCid = Cid.example,
        blockSize = blockSize.NBytes,
        datasetSize = originalDatasetSize.NBytes,
      ),
      treeCid = Cid.example,
      datasetSize = totalDatasetSize.NBytes,
      ecK = ecK - 1,
      ecM = ecM,
      strategy = Strategy,
    )

    check:
      newTestBuilderResult(localStore, mismatchManifest, tp, cellSize).error.msg ==
        "Number of blocks must be divisible by number of slots."

  test "Block size must be divisable by cell size":
    let mismatchManifest = Manifest.new(
      manifest = Manifest.new(
        treeCid = Cid.example,
        blockSize = (blockSize + 1).NBytes,
        datasetSize = (originalDatasetSize - 1).NBytes,
      ),
      treeCid = Cid.example,
      datasetSize = (totalDatasetSize - 1).NBytes,
      ecK = ecK,
      ecM = ecM,
      strategy = Strategy,
    )

    check:
      newTestBuilderResult(localStore, mismatchManifest, tp, cellSize).error.msg ==
        "Block size must be divisible by cell size."

  test "Should build correct slot builder":
    builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    check:
      builder.cellSize == cellSize
      builder.numSlots == numSlots
      builder.numBlockCells == numBlockCells
      builder.numSlotBlocks == numSlotBlocksTotal
      builder.numSlotCells == (numSlotBlocksTotal + parityPerSlot) * numBlockCells
      builder.numBlocks == numBlocksTotal

  test "Should build slot hashes for all slots":
    let
      linearStrategy = Strategy.init(
        0, protectedManifest.blocksCount - 1, numSlots, numSlots, numPadSlotBlocks
      )

      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    for i in 0 ..< numSlots:
      let
        expectedHashes = collect(newSeq):
          for j, idx in linearStrategy.getIndices(i):
            if j > (protectedManifest.numSlotBlocks - 1):
              emptyDigest
            else:
              SpongeMerkle.digest(datasetBlocks[idx].data, cellSize.int)

        cellHashes = (await builder.getCellHashes(i)).tryGet()

      check:
        cellHashes.len == expectedHashes.len
        cellHashes == expectedHashes

  test "Should build slot trees for all slots":
    let
      linearStrategy = Strategy.init(
        0, protectedManifest.blocksCount - 1, numSlots, numSlots, numPadSlotBlocks
      )

      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    for i in 0 ..< numSlots:
      let
        expectedDataHashes = collect(newSeq):
          for j, idx in linearStrategy.getIndices(i):
            if j > (protectedManifest.numSlotBlocks - 1):
              emptyDigest
            else:
              SpongeMerkle.digest(datasetBlocks[idx].data, cellSize.int)

        parityCids =
          (await builder.encodeSlot(i, protectedManifest.treeCid, tp)).tryGet()
        expectedParityHashes = collect(newSeq):
          for cid in parityCids:
            let blk = (await localStore.getBlock(cid)).tryGet()
            SpongeMerkle.digest(blk.data, cellSize.int)

        expectedRoot = Merkle.digest(expectedDataHashes & expectedParityHashes)
        slotTree = (
          await builder.buildSlotTree(
            i, protectedManifest.treeCid, protectedManifest.treeCid, tp
          )
        ).tryGet()

      check:
        slotTree.root().tryGet() == expectedRoot

  test "Should persist trees for all slots":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    for i in 0 ..< numSlots:
      discard (await builder.encodeSlot(i, protectedManifest.treeCid, tp)).tryGet()
      let
        slotTree = (
          await builder.buildSlotTree(
            i, protectedManifest.treeCid, protectedManifest.treeCid, tp
          )
        ).tryGet()
        slotRoot = (
          await builder.sealSlot(
            i, protectedManifest.treeCid, protectedManifest.treeCid, tp
          )
        ).tryGet()
        slotCid = slotRoot.toSlotCid().tryGet()
        totalLeaves = builder.numSlotBlocks + parityPerSlot

      # every composite leaf carries cell metadata and a proof matching the tree
      for cellIndex in 0 ..< totalLeaves:
        let
          (cellCid, proof) =
            (await localStore.getCidAndProof(slotCid, cellIndex)).tryGet()
          verifiableProof = proof.unsafeGet().toVerifiableProof().tryGet()
          posProof = slotTree.getProof(cellIndex).tryGet()

        check:
          verifiableProof.path == posProof.path
          verifiableProof.index == posProof.index
          verifiableProof.nleaves == posProof.nleaves

      # data-region pad leaves (positions >= dataBlocksPerSlot) carry an
      # empty blkCid; parity leaves carry their parity block's cid
      for cellIndex in 0 ..< totalLeaves:
        let leaf =
          (await localStore.getLeafMetadata(slotCid, cellIndex.Natural)).tryGet()
        if cellIndex < builder.numSlotBlocks and
            cellIndex >= protectedManifest.dataBlocksPerSlot:
          check leaf.blkCid.isEmpty
        else:
          check not leaf.blkCid.isEmpty

  test "Should build correct verification root":
    let
      linearStrategy = Strategy.init(
        0, protectedManifest.blocksCount - 1, numSlots, numSlots, numPadSlotBlocks
      )
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    (await builder.buildSlots(tp)).tryGet
    let
      verifiableRoot = !builder.verifiableRoot
      slotsHashes = collect(newSeq):
        for i in 0 ..< numSlots:
          let
            dataHashes = collect(newSeq):
              for j, idx in linearStrategy.getIndices(i):
                if j > (protectedManifest.numSlotBlocks - 1):
                  emptyDigest
                else:
                  SpongeMerkle.digest(datasetBlocks[idx].data, cellSize.int)

            parityHashes = collect(newSeq):
              for p in 0 ..< parityPerSlot:
                let blk = (
                  await localStore.getBlock(
                    verifiableRoot,
                    (protectedManifest.protectedBlocksCount + i * parityPerSlot + p).Natural,
                  )
                ).tryGet()
                SpongeMerkle.digest(blk.data, cellSize.int)

          Merkle.digest(dataHashes & parityHashes)

      expectedRoot = Merkle.digest(slotsHashes)
      rootHash = builder.buildVerifyTree(builder.slotRoots).tryGet().root.tryGet()

    check:
      expectedRoot == rootHash

  test "Should build correct verification root manifest":
    let
      linearStrategy = Strategy.init(
        0, protectedManifest.blocksCount - 1, numSlots, numSlots, numPadSlotBlocks
      )
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      manifest = (await builder.buildManifest(tp)).tryGet()

      slotsHashes = collect(newSeq):
        for i in 0 ..< numSlots:
          let
            dataHashes = collect(newSeq):
              for j, idx in linearStrategy.getIndices(i):
                if j > (protectedManifest.numSlotBlocks - 1):
                  emptyDigest
                else:
                  SpongeMerkle.digest(datasetBlocks[idx].data, cellSize.int)

            parityHashes = collect(newSeq):
              for p in 0 ..< parityPerSlot:
                let blk = (
                  await localStore.getBlock(
                    manifest.treeCid,
                    (manifest.protectedBlocksCount + i * parityPerSlot + p).Natural,
                  )
                ).tryGet()
                SpongeMerkle.digest(blk.data, cellSize.int)

          Merkle.digest(dataHashes & parityHashes)

      expectedRoot = Merkle.digest(slotsHashes)
      mhash = manifest.verifyRoot.mhash.tryGet()
      mhashBytes = mhash.digestBytes
      rootHash = !Poseidon2Hash.fromBytes(mhashBytes.toArray32)

    check:
      expectedRoot == rootHash

  test "Should not build from verifiable manifest with 0 slots":
    var
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      verifyManifest = (await builder.buildManifest(tp)).tryGet()

    verifyManifest.slotRoots = @[]
    check newTestBuilderResult(localStore, verifyManifest, tp, cellSize).isErr

  test "Should not build from verifiable manifest with incorrect number of slots":
    var
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

      verifyManifest = (await builder.buildManifest(tp)).tryGet()

    verifyManifest.slotRoots.del(verifyManifest.slotRoots.len - 1)

    check newTestBuilderResult(localStore, verifyManifest, tp, cellSize).isErr

  test "Should not build from verifiable manifest with invalid verify root":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    var verifyManifest = (await builder.buildManifest(tp)).tryGet()

    rng.shuffle(Rng.instance, verifyManifest.verifyRoot.data.buffer)

    check newTestBuilderResult(localStore, verifyManifest, tp, cellSize).isErr

  test "Should build from verifiable manifest":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

      verifyManifest = (await builder.buildManifest(tp)).tryGet()

      verificationBuilder = newTestBuilder(localStore, verifyManifest, tp, cellSize)

    check:
      builder.slotRoots == verificationBuilder.slotRoots
      builder.verifyRoot == verificationBuilder.verifyRoot

suite "Cell-aware slot building":
  ## Tests for slot building that verify cell leaves are stored correctly
  ## with separate cellCid and blkCid for proper refcount handling.
  ##
  let
    blockSize = NBytes 1024
    cellSize = NBytes 64
    ecK = 2
    ecM = 1

    numSlots = ecK + ecM
    numDatasetBlocks = 3
    numTotalBlocks = calcEcBlocksCount(numDatasetBlocks, ecK, ecM)
    originalDatasetSize = numDatasetBlocks * blockSize.int
    totalDatasetSize = numTotalBlocks * blockSize.int

    numSlotBlocks = numTotalBlocks div numSlots
    numBlockCells = (blockSize div cellSize).int
    numSlotCells = numSlotBlocks * numBlockCells
    pow2SlotCells = nextPowerOfTwo(numSlotCells)
    numPadSlotBlocks = (pow2SlotCells div numBlockCells) - numSlotBlocks
    parityPerSlot = 3 * (numSlotBlocks + numPadSlotBlocks)

    emptyDigest = SpongeMerkle.digest(newSeqWith(blockSize.int, 0xFF'u8), cellSize.int)

  var
    datasetBlocks: seq[bt.Block]
    localStore: RepoStore
    manifest: Manifest
    protectedManifest: Manifest
    tp: Taskpool

  setup:
    tp = Taskpool.new(num_threads = 4)
    let
      repoDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()
      metaDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()

    localStore = RepoStore.new(repoDs, metaDs)
    let chunker =
      RandomChunker.new(Rng.instance(), size = totalDatasetSize, chunkSize = blockSize)
    datasetBlocks = await chunker.createBlocks()

    (manifest, protectedManifest) = await createProtectedManifest(
      datasetBlocks, localStore, numDatasetBlocks, ecK, ecM, blockSize,
      originalDatasetSize, totalDatasetSize,
    )

  teardown:
    await localStore.close()
    tp.shutdown()
    reset(datasetBlocks)
    reset(localStore)
    reset(manifest)
    reset(protectedManifest)

  test "buildSlot stores cell leaves with correct cellCid and blkCid":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    discard (await builder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
    let slotRoot = (
      await builder.sealSlot(
        0, protectedManifest.treeCid, protectedManifest.treeCid, tp
      )
    ).tryGet()
    let slotCid = slotRoot.toSlotCid().tryGet()

    # Verify that every composite leaf has cell metadata set
    for i in 0 ..< builder.numSlotBlocks + parityPerSlot:
      let leaf = (await localStore.getLeafMetadata(slotCid, i.Natural)).tryGet()
      check:
        leaf.isCell == true
        leaf.blkCid != Cid() # blkCid should point to a real block

  test "buildSlot stores proofs for pad blocks with empty blkCid":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    discard (await builder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
    let slotRoot = (
      await builder.sealSlot(
        0, protectedManifest.treeCid, protectedManifest.treeCid, tp
      )
    ).tryGet()
    let slotCid = slotRoot.toSlotCid().tryGet()

    # ALL positions (data + parity leaves) should have leaf metadata
    let numRealBlocks = protectedManifest.dataBlocksPerSlot
    let numTotalSlotBlocks = builder.numSlotBlocks

    for i in 0 ..< numTotalSlotBlocks + parityPerSlot:
      let leafRes = await localStore.getLeafMetadata(slotCid, i.Natural)
      check leafRes.isOk

    # If there are pad blocks in the DATA region, their blkCid should be
    # empty CID (parity leaves carry their parity block's cid)
    if numTotalSlotBlocks > numRealBlocks:
      for i in numRealBlocks ..< numTotalSlotBlocks:
        let leaf = (await localStore.getLeafMetadata(slotCid, i.Natural)).tryGet()
        check leaf.blkCid.isEmpty

  test "buildSlot increments refcount on blkCid, not cellCid":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    # Build one slot
    discard (await builder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
    let slotRoot = (
      await builder.sealSlot(
        0, protectedManifest.treeCid, protectedManifest.treeCid, tp
      )
    ).tryGet()
    let slotCid = slotRoot.toSlotCid().tryGet()

    # Get the first block's CID and check its refcount
    let leaf = (await localStore.getLeafMetadata(slotCid, 0.Natural)).tryGet()
    let blkRefCount = (await localStore.blockRefCount(leaf.blkCid)).tryGet()

    # Refcount should be at least 1 (this slot references it)
    check blkRefCount >= 1

    # Cell CID should not have a block metadata entry
    let cellRefCountRes = await localStore.blockRefCount(leaf.cellCid)
    check cellRefCountRes.isErr or cellRefCountRes.tryGet() == 0

  test "Multiple slots referencing same block increment refcount correctly":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    # Build all slots
    (await builder.buildSlots(tp)).tryGet()

    # Get refcount on first dataset block
    let firstBlockCid = datasetBlocks[0].cid
    let refCount = (await localStore.blockRefCount(firstBlockCid)).tryGet()

    # Refcount should be 1 (block is referenced by one slot in EC distribution)
    check refCount >= 1
