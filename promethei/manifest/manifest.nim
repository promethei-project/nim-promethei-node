## Copyright (c) 2025 Promethei Authors
## Copyright (c) 2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

# This module defines all operations on Manifest

{.push raises: [].}

import pkg/libp2p/protobuf/minprotobuf
import pkg/libp2p/[cid, multihash, multicodec]
import pkg/questionable/results
import std/math

import ../errors
import ../utils
import ../utils/json
import ../units
import ../blocktype
import ../indexingstrategy
import ../logutils

# TODO: Manifest should be reworked to more concrete types,
# perhaps using inheritance
type Manifest* = ref object of RootObj
  treeCid {.serialize.}: Cid # Root of the merkle tree
  datasetSize {.serialize.}: NBytes # Total size of all blocks
  blockSize {.serialize.}: NBytes
    # Size of each contained block (might not be needed if blocks are len-prefixed)
  codec: MultiCodec # Dataset codec
  hcodec: MultiCodec # Multihash codec
  cidVersion: CidVersion # Cid version
  version: uint32 # Manifest version
  filename {.serialize.}: ?string # The filename of the content uploaded (optional)
  mimetype {.serialize.}: ?string # The mimetype of the content uploaded (optional)
  case protected {.serialize.}: bool # Protected datasets have erasure coded info
  of true:
    ecK: int # Number of blocks to encode
    ecM: int # Number of resulting parity blocks
    originalTreeCid: Cid # The original root of the dataset being erasure coded
    originalDatasetSize: NBytes
    protectedStrategy: StrategyType # Indexing strategy used to build the slot roots
    case verifiable {.serialize.}: bool
    # Verifiable datasets can be used to generate storage proofs
    of true:
      innerK: uint32 # inner cell code data shards (K)
      innerN: uint32 # inner cell code total shards (N)
      verifyRoot: Cid # Root of the top level merkle tree built from slot roots
      slotRoots: seq[Cid] # Individual slot root built from the original dataset blocks
      cellSize: NBytes # Size of each slot cell
      verifiableStrategy: StrategyType # Indexing strategy used to build the slot roots
      protectedTreeCid: Cid
        # Root of the protected tree (verifiable view of the protected dataset)
      protectedDatasetSize: NBytes # Physical size of the protected dataset
    else:
      discard
  else:
    discard

const ManifestVersionV1* = 1'u32 # v1.0.0: locks cidVersion = CIDv1, parity packing
const DefaultInnerK* = 1'u32 # inner cell code data shards (K); rate 1/2 = (1, 2)
const DefaultInnerN* = 2'u32 # inner cell code total shards (N)
  # inner cell-code parity shards per data shard (1 = rate 1/2)

############################################################
# Accessors
############################################################

func blockSize*(self: Manifest): NBytes =
  self.blockSize

func datasetSize*(self: Manifest): NBytes =
  self.datasetSize

func version*(self: Manifest): uint32 =
  self.version

func cidVersion*(self: Manifest): CidVersion =
  self.cidVersion

func innerK*(self: Manifest): uint32 =
  self.innerK

func innerN*(self: Manifest): uint32 =
  self.innerN

func innerParityFactor*(self: Manifest): int =
  # parity shards per data shard: (N-K)/K must divide exactly (1/2 -> 1)
  (self.innerN.int - self.innerK.int) div self.innerK.int

func hcodec*(self: Manifest): MultiCodec =
  self.hcodec

func codec*(self: Manifest): MultiCodec =
  self.codec

func protected*(self: Manifest): bool =
  self.protected

func ecK*(self: Manifest): int =
  self.ecK

func ecM*(self: Manifest): int =
  self.ecM

func originalTreeCid*(self: Manifest): Cid =
  self.originalTreeCid

func originalBlocksCount*(self: Manifest): int =
  divUp(self.originalDatasetSize.int, self.blockSize.int)

func originalDatasetSize*(self: Manifest): NBytes =
  self.originalDatasetSize

func treeCid*(self: Manifest): Cid =
  self.treeCid

func blocksCount*(self: Manifest): int =
  divUp(self.datasetSize.int, self.blockSize.int)

func verifiable*(self: Manifest): bool =
  bool (self.protected and self.verifiable)

func verifyRoot*(self: Manifest): Cid =
  self.verifyRoot

func slotRoots*(self: Manifest): seq[Cid] =
  self.slotRoots

func numSlots*(self: Manifest): int =
  self.ecK + self.ecM

func cellSize*(self: Manifest): NBytes =
  self.cellSize

func protectedStrategy*(self: Manifest): StrategyType =
  self.protectedStrategy

func verifiableStrategy*(self: Manifest): StrategyType =
  self.verifiableStrategy

func protectedTreeCid*(self: Manifest): Cid =
  self.protectedTreeCid

func protectedDatasetSize*(self: Manifest): NBytes =
  self.protectedDatasetSize

func protectedBlocksCount*(self: Manifest): int =
  # Protected partition of a verifiable manifest (physical size); blocksCount otherwise
  if self.verifiable:
    divUp(self.protectedDatasetSize.int, self.blockSize.int)
  else:
    self.blocksCount

func dataBlocksPerSlot*(self: Manifest): int =
  # Exact when verify() holds; LinearStrategy clamps to lastIndex otherwise
  divUp(self.protectedBlocksCount, self.numSlots)

func numSlotBlocks*(self: Manifest): int =
  divUp(self.blocksCount, self.numSlots)

func slotSize*(self: Manifest): NBytes =
  (self.blockSize.int * self.numSlotBlocks).NBytes

# 2.5D geometry
func numBlockCells*(self: Manifest): int =
  # - cellSize lives in the verifiable branch
  # - non-verifiable manifests use the default
  # (consistent with a default-constructed builder)

  let cellSize = if self.verifiable: self.cellSize else: DefaultCellSize
  self.blockSize.int div cellSize.int

func numPadSlotBlocks*(self: Manifest): int =
  nextPowerOfTwo(self.dataBlocksPerSlot * self.numBlockCells) div self.numBlockCells -
    self.dataBlocksPerSlot

func numSlotBlocksTotal*(self: Manifest): int =
  self.dataBlocksPerSlot + self.numPadSlotBlocks

func firstPassParityBlocks*(self: Manifest): int =
  self.numSlotBlocksTotal * self.innerParityFactor

func secondPassParityBlocks*(self: Manifest): int =
  (1 + self.innerParityFactor) * self.numSlotBlocksTotal * self.innerParityFactor

func parityBlocksPerSlot*(self: Manifest): int =
  self.firstPassParityBlocks + self.secondPassParityBlocks

func filename*(self: Manifest): ?string =
  self.filename

func mimetype*(self: Manifest): ?string =
  self.mimetype

############################################################
# Operations on block list
############################################################

func isManifest*(cid: Cid): ?!bool =
  success (ManifestCodec == ?cid.contentType().mapFailure(PrometheiError))

func isManifest*(mc: MultiCodec): ?!bool =
  success mc == ManifestCodec

proc getBlocksIterator*(self: Manifest): Iter[int] =
  Iter[int].new(0 ..< self.blocksCount)

proc getOriginalIterator*(self: Manifest): ?!Iter[int] =
  if not self.protected:
    return failure("Manifest is not protected")
  success Iter[int].new(0 ..< self.originalBlocksCount)

proc getSlotIterator*(self: Manifest, slotIdx: int): ?!Iter[int] =
  if not self.protected:
    return failure("Manifest is not protected")
  if not self.verifiable:
    return failure("Manifest is not verifiable")

  without indexer =?
    self.verifiableStrategy.init(0, self.protectedBlocksCount - 1, self.numSlots).catch,
    err:
    error "Unable to create indexing strategy from protected manifest", err = err.msg
    return failure(err)

  without blksIter =? indexer.getIndices(slotIdx).catch, err:
    error "Unable to get indices from strategy", err = err.msg
    return failure(err)

  let
    slot = slotIdx
    parityPerSlot = self.parityBlocksPerSlot
    protectedCount = self.protectedBlocksCount
  success Iter[int].new(
    iterator (): int {.gcsafe.} =
      for v in blksIter:
        yield v # data indices (real indices only; no synthetic pads)
      for i in 0 ..< parityPerSlot:
        yield protectedCount + slot * parityPerSlot + i

  ) # position(slot, i)

############################################################
# Various sizes and verification
############################################################

func rounded*(self: Manifest): int =
  ## Number of data blocks in *protected* manifest including padding at the end
  roundUp(self.originalBlocksCount, self.ecK)

func steps*(self: Manifest): int =
  ## Number of EC groups in *protected* manifest
  divUp(self.rounded, self.ecK)

func verify*(self: Manifest): ?!void =
  ## Check manifest correctness
  ##

  if self.innerK == 0 or (
    (self.innerN.int - self.innerK.int) mod self.innerK.int != 0
  ):
    return
      failure newException(ArchivistError, "Broken manifest: inner code rate not supported")

  if self.protected and (
    self.protectedBlocksCount != self.steps * (self.ecK + self.ecM)
  ):
    return
      failure newException(PrometheiError, "Broken manifest: wrong originalBlocksCount")

  return success()

func `==`*(a, b: Manifest): bool =
  (a.treeCid == b.treeCid) and (a.datasetSize == b.datasetSize) and
    (a.blockSize == b.blockSize) and (a.version == b.version) and
    (a.cidVersion == b.cidVersion) and (a.innerK == b.innerK) and (a.innerN == b.innerN) and
    (a.hcodec == b.hcodec) and (a.codec == b.codec) and (a.protected == b.protected) and
    (a.filename == b.filename) and (a.mimetype == b.mimetype) and (
    if a.protected:
      (a.ecK == b.ecK) and (a.ecM == b.ecM) and (a.originalTreeCid == b.originalTreeCid) and
        (a.originalDatasetSize == b.originalDatasetSize) and
        (a.protectedStrategy == b.protectedStrategy) and (a.verifiable == b.verifiable) and
      (
        if a.verifiable:
          (a.verifyRoot == b.verifyRoot) and (a.slotRoots == b.slotRoots) and
            (a.cellSize == b.cellSize) and (
            a.verifiableStrategy == b.verifiableStrategy
          ) and (a.protectedTreeCid == b.protectedTreeCid) and
            (a.protectedDatasetSize == b.protectedDatasetSize)
        else:
          true
      )
    else:
      true
  )

func `$`*(self: Manifest): string =
  result =
    "treeCid: " & $self.treeCid & ", datasetSize: " & $self.datasetSize & ", blockSize: " &
    $self.blockSize & ", version: " & $self.version & ", cidVersion: " & $self.cidVersion &
    ", innerK: " & $self.innerK & ", innerN: " & $self.innerN & ", hcodec: " & $self.hcodec & ", codec: " &
    $self.codec & ", protected: " & $self.protected

  if self.filename.isSome:
    result &= ", filename: " & $self.filename

  if self.mimetype.isSome:
    result &= ", mimetype: " & $self.mimetype

  result &= (
    if self.protected:
      ", ecK: " & $self.ecK & ", ecM: " & $self.ecM & ", originalTreeCid: " &
        $self.originalTreeCid & ", originalDatasetSize: " & $self.originalDatasetSize &
        ", verifiable: " & $self.verifiable & (
        if self.verifiable:
          ", verifyRoot: " & $self.verifyRoot & ", slotRoots: " & $self.slotRoots &
            ", protectedTreeCid: " & $self.protectedTreeCid & ", protectedDatasetSize: " &
            $self.protectedDatasetSize
        else:
          ""
      )
    else:
      ""
  )

  return result

############################################################
# Constructors
############################################################

func new*(
    T: type Manifest,
    treeCid: Cid,
    blockSize: NBytes,
    datasetSize: NBytes,
    version: uint32 = ManifestVersionV1,
    cidVersion: CidVersion = CIDv1,
    innerK: uint32 = DefaultInnerK,
    innerN: uint32 = DefaultInnerN,
    hcodec = Sha256HashCodec,
    codec = BlockCodec,
    protected = false,
    filename: ?string = string.none,
    mimetype: ?string = string.none,
): Manifest =
  T(
    treeCid: treeCid,
    blockSize: blockSize,
    datasetSize: datasetSize,
    version: version,
    cidVersion: cidVersion,
    innerK: innerK,
    innerN: innerN,
    codec: codec,
    hcodec: hcodec,
    protected: protected,
    filename: filename,
    mimetype: mimetype,
  )

func new*(
    T: type Manifest,
    manifest: Manifest,
    treeCid: Cid,
    datasetSize: NBytes,
    ecK, ecM: int,
    strategy = SteppedStrategy,
): Manifest =
  ## Create an erasure protected dataset from an
  ## unprotected one
  ##

  Manifest(
    treeCid: treeCid,
    datasetSize: datasetSize,
    version: manifest.version,
    cidVersion: manifest.cidVersion,
    innerK: manifest.innerK,
    innerN: manifest.innerN,
    codec: manifest.codec,
    hcodec: manifest.hcodec,
    blockSize: manifest.blockSize,
    protected: true,
    ecK: ecK,
    ecM: ecM,
    originalTreeCid: manifest.treeCid,
    originalDatasetSize: manifest.datasetSize,
    protectedStrategy: strategy,
    filename: manifest.filename,
    mimetype: manifest.mimetype,
  )

func new*(T: type Manifest, manifest: Manifest): Manifest =
  ## Create an unprotected dataset from an
  ## erasure protected one
  ##

  Manifest(
    treeCid: manifest.originalTreeCid,
    datasetSize: manifest.originalDatasetSize,
    version: manifest.version,
    cidVersion: manifest.cidVersion,
    innerK: manifest.innerK,
    innerN: manifest.innerN,
    codec: manifest.codec,
    hcodec: manifest.hcodec,
    blockSize: manifest.blockSize,
    protected: false,
    filename: manifest.filename,
    mimetype: manifest.mimetype,
  )

func new*(
    T: type Manifest,
    treeCid: Cid,
    datasetSize: NBytes,
    blockSize: NBytes,
    version: uint32 = ManifestVersionV1,
    cidVersion: CidVersion = CIDv1,
    innerK: uint32 = DefaultInnerK,
    innerN: uint32 = DefaultInnerN,
    hcodec: MultiCodec,
    codec: MultiCodec,
    ecK: int,
    ecM: int,
    originalTreeCid: Cid,
    originalDatasetSize: NBytes,
    strategy = SteppedStrategy,
    filename: ?string = string.none,
    mimetype: ?string = string.none,
): Manifest =
  Manifest(
    treeCid: treeCid,
    datasetSize: datasetSize,
    blockSize: blockSize,
    version: version,
    cidVersion: cidVersion,
    innerK: innerK,
    innerN: innerN,
    hcodec: hcodec,
    codec: codec,
    protected: true,
    ecK: ecK,
    ecM: ecM,
    originalTreeCid: originalTreeCid,
    originalDatasetSize: originalDatasetSize,
    protectedStrategy: strategy,
    filename: filename,
    mimetype: mimetype,
  )

func new*(
    T: type Manifest,
    manifest: Manifest, # protected source
    treeCid: Cid, # verifiable sha root (top-level)
    datasetSize: NBytes, # verifiable physical size (top-level)
    verifyRoot: Cid,
    slotRoots: openArray[Cid],
    cellSize = DefaultCellSize,
    strategy = LinearStrategy,
): ?!Manifest =
  ## Create a verifiable dataset from a
  ## protected one
  ##

  if not manifest.protected:
    return failure newException(
      PrometheiError, "Can create verifiable manifest only from protected manifest."
    )

  if slotRoots.len != manifest.numSlots:
    return failure newException(PrometheiError, "Wrong number of slot roots.")

  success Manifest(
    treeCid: treeCid,
    datasetSize: datasetSize,
    version: manifest.version,
    cidVersion: manifest.cidVersion,
    innerK: manifest.innerK,
    innerN: manifest.innerN,
    codec: manifest.codec,
    hcodec: manifest.hcodec,
    blockSize: manifest.blockSize,
    protected: true,
    ecK: manifest.ecK,
    ecM: manifest.ecM,
    originalTreeCid: manifest.originalTreeCid,
    originalDatasetSize: manifest.originalDatasetSize,
    protectedStrategy: manifest.protectedStrategy,
    verifiable: true,
    verifyRoot: verifyRoot,
    slotRoots: @slotRoots,
    cellSize: cellSize,
    verifiableStrategy: strategy,
    protectedTreeCid: manifest.treeCid,
    protectedDatasetSize: manifest.datasetSize,
    filename: manifest.filename,
    mimetype: manifest.mimetype,
  )

func new*(T: type Manifest, data: openArray[byte]): ?!Manifest =
  ## Create a manifest instance from given data
  ##

  Manifest.decode(data)

func protectedView*(self: Manifest): ?!Manifest =
  ## Protected (non-verifiable) view of a verifiable manifest;
  ## repair addressing uses the protected root
  if not self.verifiable:
    return failure newException(ArchivistError, "Manifest is not verifiable")
  success Manifest(
    treeCid: self.protectedTreeCid,
    datasetSize: self.protectedDatasetSize,
    version: self.version,
    cidVersion: self.cidVersion,
    innerK: self.innerK,
    innerN: self.innerN,
    codec: self.codec,
    hcodec: self.hcodec,
    blockSize: self.blockSize,
    protected: true,
    ecK: self.ecK,
    ecM: self.ecM,
    originalTreeCid: self.originalTreeCid,
    originalDatasetSize: self.originalDatasetSize,
    protectedStrategy: self.protectedStrategy,
    filename: self.filename,
    mimetype: self.mimetype,
  )
