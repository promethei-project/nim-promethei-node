## Copyright (c) 2025 Promethei Authors
## Copyright (c) 2023 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

{.push raises: [].}

import std/math
import std/sequtils
import std/sugar

import pkg/iter
import pkg/libp2p
import pkg/chronos
import pkg/questionable
import pkg/questionable/results
import pkg/taskpools
import pkg/constantine/math/io/io_fields

import ../../logutils
import ../../utils
import ../../utils/poseidon2digest
import ../../stores
import ../../manifest
import ../../merkletree
import ../../merkletree/asyncposeidon2
import ../../indexingstrategy
import ../../prometheitypes
import ../../erasure
import ../../errors
import ../../blocktype as bt

import ../converters

export converters, iter, asyncposeidon2

logScope:
  topics = "promethei slotsbuilder"

const DefaultSlotBuildConcurrency* = 4

type SlotsBuilder*[SomeTree, SomeHash] = ref object of RootObj
  networkStore: BlockStore
  repoStore: RepoStore
  manifest: Manifest # current manifest
  strategy: IndexingStrategy # indexing strategy
  cellSize: NBytes # cell size
  numSlotBlocks: Natural
    # number of blocks per slot (should yield a power of two number of cells)
  slotRoots: seq[SomeHash] # roots of the slots
  emptyBlock: seq[byte] # empty block
  verifiableTree: ?SomeTree # verification tree (dataset tree)
  emptyDigestTree: SomeTree # empty digest tree for empty blocks
  erasure: Erasure # 2.5D inner-code encoder
  parityRoot: ?Cid
    # root under which parity blocks live (tmpCid during client build;
    # manifest.treeCid for a provider/verifiable builder)
  verifiableRoot: ?Cid # verifiable sha root, set by buildSlots from the finalize result

func verifiable*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): bool {.inline.} =
  ## Returns true if the slots are verifiable.
  ##

  self.manifest.verifiable

func slotRoots*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): seq[SomeHash] {.inline.} =
  ## Returns the slot roots.
  ##

  self.slotRoots

func verifyTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): ?SomeTree {.inline.} =
  ## Returns the slots tree (verification tree).
  ##

  self.verifiableTree

func verifyRoot*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): ?SomeHash {.inline.} =
  ## Returns the slots root (verification root).
  ##

  if tree =? self.verifyTree and root =? tree.root:
    return some root

func numSlots*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): Natural =
  ## Number of slots.
  ##

  self.manifest.numSlots

func numSlotBlocks*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  ## Number of blocks per slot.
  ##

  self.numSlotBlocks

func numSlotBlocksTotal*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  ## Number of blocks per slot including pow2 pads (the slot tree's data leaves).
  ##

  self.numSlotBlocks

func verifiableRoot*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): ?Cid =
  ## Verifiable sha tree root, set after a client build.
  ##

  self.verifiableRoot

func numBlocks*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): Natural =
  ## Number of blocks.
  ##

  self.numSlotBlocks * self.manifest.numSlots

func numBlockCells*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  ## Number of cells per block.
  ##

  (self.manifest.blockSize div self.cellSize).Natural

func cellSize*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): NBytes =
  ## Cell size.
  ##

  self.cellSize

func numSlotCells*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  ## Number of cells per slot - the FULL sampling space (data, pad, and
  ## parity leaves)
  ##

  self.numBlockCells * (
    self.numSlotBlocks +
    self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)
  )

func slotIndicesIter*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], slot: Natural
): ?!Iter[int] =
  ## Returns the slot indices.
  ##

  self.strategy.getIndices(slot).catch

func slotIndices*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], slot: Natural
): ?!seq[int] =
  ## Returns the slot indices.
  ##

  success toSeq(?catch(self.strategy.getIndices(slot)))

func manifest*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): Manifest =
  ## Returns the manifest.
  ##

  self.manifest

proc buildBlockTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], root: Cid, blkIdx: Natural, slotPos: Natural
): Future[?!(seq[byte], SomeTree)] {.async: (raises: [CancelledError]).} =
  ## Build the block digest tree and return a tuple with the
  ## block data and the tree.
  ##
  ## `root` is the tree the block is read from; `slotPos` is the leaf
  ## position within the slot - data-region pad positions (>= dataBlocksPerSlot)
  ## yield the empty digest tree. Parity leaves are handled by the callers.
  ##

  logScope:
    root = root
    blkIdx = blkIdx
    slotPos = slotPos
    dataBlocksPerSlot = self.manifest.dataBlocksPerSlot
    cellSize = self.cellSize

  trace "Building block tree"
  if slotPos > (self.manifest.dataBlocksPerSlot - 1):
    # pad blocks are 0 byte blocks
    trace "Returning empty digest tree for pad block"
    return success (self.emptyBlock, self.emptyDigestTree)

  let blk = ?await self.networkStore.getBlock(root, blkIdx)
  if blk.isEmpty:
    return success (self.emptyBlock, self.emptyDigestTree)

  let tree = ?SomeTree.digestTree(blk.data, self.cellSize.int)
  success (blk.data, tree)

proc getStoredCid*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], root: Cid, index: Natural
): Future[?!Cid] {.async: (raises: [CancelledError]).} =
  ## Leaf CID at `index` under `root`; missing leaf records (erasure
  ## zero-pads) yield the empty CID.
  ##

  let res = await self.repoStore.getCid(root, index)
  if res.isErr:
    if res.error of BlockNotFoundError:
      return
        success(?emptyCid(self.manifest.cidVersion, self.manifest.hcodec, BlockCodec))
    return failure(res.error)
  success(res.get)

proc buildVerifiableLeafCids*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Future[?!ref seq[Cid]] {.async: (raises: [CancelledError]).} =
  ## Leaf CID list for the verifiable tree: protected leaves (position
  ## order, empty CID for missing records) ++ per-slot parity leaves
  ## (position order, read from the parity root).
  ##

  let
    protectedCount = self.manifest.protectedBlocksCount
    parityPerSlot =
      self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)
  var leafCids = newSeq[Cid](protectedCount + self.manifest.numSlots * parityPerSlot)
  for idx in 0 ..< protectedCount:
    leafCids[idx] = ?await self.getStoredCid(self.manifest.treeCid, idx.Natural)

  without parityRoot =? self.parityRoot, e:
    return failure(e)
  for pos in protectedCount ..< leafCids.len:
    leafCids[pos] = ?await self.getStoredCid(parityRoot, pos.Natural)

  var cids = seq[Cid].new()
  cids[] = move leafCids
  success cids

proc getCellHashes*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], slotIndex: Natural
): Future[?!seq[SomeHash]] {.async: (raises: [CancelledError]).} =
  ## Collect all the cells from a block and return
  ## their hashes.
  ##

  let
    treeCid = self.manifest.treeCid
    blockCount = self.manifest.blocksCount
    numberOfSlots = self.manifest.numSlots

  logScope:
    treeCid = treeCid
    origBlockCount = blockCount
    numberOfSlots = numberOfSlots
    slotIndex = slotIndex

  let hashes = collect(newSeq):
    for i, blkIdx in ?catch(self.strategy.getIndices(slotIndex)):
      logScope:
        blkIdx = blkIdx
        pos = i

      trace "Getting block CID for tree at index"
      let
        (_, tree) = ?await self.buildBlockTree(self.manifest.treeCid, blkIdx, i)
        digest = ?tree.root

      trace "Get block digest", digest = digest.toHex
      digest

  success hashes

proc getSlotLeafBlock*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash],
    slotIndex: Natural,
    dataRoot: Cid,
    parityRoot: Cid,
    slotPos: Natural,
): Future[?!(seq[byte], SomeTree)] {.async: (raises: [CancelledError]).} =
  ## Block data + digest tree for a slot leaf position `slotPos` - the one
  ## flat position function over the slot's leaves:
  ##
  ##   p <  numSlotBlocksTotal -> strategy index (outer-EC interleave)
  ##   p >= numSlotBlocksTotal -> protectedBlocksCount + slot*parityPerSlot + (p - T)
  ##
  ## Data pads yield the empty digest tree; parity blocks are read from
  ## `parityRoot`.
  ##

  if slotPos < self.numSlotBlocks:
    let indices = ?self.slotIndices(slotIndex)
    success(?await self.buildBlockTree(dataRoot, indices[slotPos], slotPos))
  else:
    let
      protectedCount = self.manifest.protectedBlocksCount
      parityPerSlot = self.manifest.parityBlocksPerSlot(
        self.numBlockCells.int, self.numSlotBlocks.int
      )
      blk =
        ?await self.networkStore.getBlock(
          parityRoot,
          protectedCount + slotIndex * parityPerSlot + (slotPos - self.numSlotBlocks),
        )
    if blk.isEmpty:
      return failure "Empty parity block"
    let tree = ?SomeTree.digestTree(blk.data, self.cellSize.int)
    success((blk.data, tree))

proc buildSlotTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash],
    slotIndex: Natural,
    dataRoot: Cid,
    parityRoot: Cid,
    tp: Taskpool,
): Future[?!SomeTree] {.async: (raises: [CancelledError]).} =
  ## Build the slot tree from the block digest hashes, streaming them into
  ## the async tree builder so layer compression runs on the taskpool while
  ## the block digest trees are fetched.
  ##
  ## The slot's leaves are the data blocks (strategy indices, consumed by
  ## slot position; pad positions past the data count yield the empty digest
  ## root, mirroring getCellHashes) followed by the parity blocks at
  ## positions `position(slotIndex, i)` under `parityRoot`.
  ##

  let
    dataLeaves = self.numSlotBlocks
    parityLeaves =
      self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)

  proc digestAt(pos: int): Future[SomeHash] {.async.} =
    ## Root of the block digest tree at slot leaf position `pos`; raises on
    ## fetch or build failure (the async tree builder surfaces it as a failed leaf).
    let (_, tree) =
      (await self.getSlotLeafBlock(slotIndex, dataRoot, parityRoot, pos.Natural)).tryGet
    return tree.root.tryGet

  let
    items =
      mapAsync[int, SomeHash](Iter[int].new(0 ..< dataLeaves + parityLeaves), digestAt)
    tree = ?await SomeTree.buildAsync(items, tp)

  success tree

proc sealSlot*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash],
    slotIndex: Natural,
    dataRoot: Cid,
    parityRoot: Cid,
    tp: Taskpool,
): Future[?!SomeHash] {.async: (raises: [CancelledError]).} =
  ## Seal a slot: build the slot tree over the data + parity block digests
  ## and store the proofs in the block store. Parity CIDs are derived from
  ## `parityRoot` + geometry (the parity block's CID doubles as the leaf's
  ## blkCid - no separate CID list).
  ##

  logScope:
    dataRoot = dataRoot
    parityRoot = parityRoot
    slotIndex = slotIndex

  trace "Sealing slot tree"

  without tree =? (await self.buildSlotTree(slotIndex, dataRoot, parityRoot, tp)) and
    treeCid =? tree.root .? toSlotCid, e:
    error "Failed to build slot tree", e = e.msg
    return failure(e)

  let
    indices = toSeq(?catch(self.strategy.getIndices(slotIndex)))
    dataLeaves = indices.len
    parityLeaves =
      self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)
    protectedCount = self.manifest.protectedBlocksCount

  trace "Storing slot tree", treeCid, slotIndex, leaves = tree.leavesCount
  ?await self.repoStore.withOverlay(
    treeCid,
    status = Storing.some,
    body = proc(): Future[?!void] {.closure, async: (raises: [CancelledError]).} =
      var proofItems: seq[(Natural, Cid, Cid, PrometheiProof)]
      for pos in 0 ..< dataLeaves + parityLeaves:
        without cellCid =? tree.leaves[pos].toCellCid, e:
          error "Failed to get CID for slot cell", e = e.msg
          return failure(e)

        without proof =? tree.getProof(pos) and encodableProof =? proof.toEncodableProof,
          e:
          error "Failed to get proof for slot tree", e = e.msg
          return failure(e)

        let blkCid =
          if pos < dataLeaves:
            if pos >= self.manifest.dataBlocksPerSlot:
              # pad block: no real block
              ?emptyCid(self.manifest.cidVersion, self.manifest.hcodec, BlockCodec)
            else:
              ?await self.getStoredCid(dataRoot, indices[pos])
          else:
            let blk =
              ?await self.networkStore.getBlock(
                parityRoot,
                protectedCount + slotIndex * parityLeaves + (pos - dataLeaves),
              )
            blk.cid

        proofItems.add((pos.Natural, cellCid, blkCid, encodableProof))

      ?await self.repoStore.putCellCidsAndProofs(treeCid, proofItems)
      success(),
  )

  tree.root()

proc packParityCells(
    cells: seq[byte], cellSize: int, cellsPerBlock: int
): seq[seq[byte]] =
  ## Chunk concatenated parity cells into compound blocks of `cellsPerBlock`
  ## cells, zero-padding the final block when it is not full.
  let
    blockBytes = cellsPerBlock * cellSize
    count = divUp(cells.len, blockBytes)
  for i in 0 ..< count:
    var blk = newSeqWith(blockBytes, 0'u8)
      # explicit: newSeq does not zero under -d:danger
    let
      start = i * blockBytes
      len = min(blockBytes, cells.len - start)
    blk[0 ..< len] = cells[start ..< start + len]
    result.add(blk)

proc encodeSlot*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash],
    slotIndex: Natural,
    targetRoot: Cid,
    tp: Taskpool,
): Future[?!seq[Cid]] {.async: (raises: [CancelledError]).} =
  ## Encode the slot's two 2.5D passes and write the parity blocks under
  ## `targetRoot` (the CURRENT overlay). Returns the slot's parity CIDs in
  ## position order [pass1 ++ pass2].
  ##
  ## The inner cell code runs at the layout version's rate K:N. All geometry
  ## derives from the manifest accessors:
  ##
  ## Pass 1 (row-wise): each block's C cells encode to n_row = C*N/K shards;
  ## the n_row - C parity cells per row are concatenated across rows and
  ## packed into C-cell compound blocks (tail zero-padded).
  ##
  ## Pass 2 (column-wise, a TRUE product code): each of the n_row cell-rows
  ## (data cells AND pass-1 parity cells) is encoded over the T data shards;
  ## the n_col - T parity cells per column are concatenated column-major and
  ## packed the same way. The parity-of-parity corner therefore lands in the
  ## last columns' parity, interleaved into the pass-2 region.
  ##

  logScope:
    targetRoot = targetRoot
    slotIndex = slotIndex

  trace "Encoding slot parity"
  let
    cellSize = self.cellSize.int
    C = self.numBlockCells.int # cells per block
    T = self.numSlotBlocks.int # data-region leaves incl. pow2 pads
    nRow = self.manifest.rowShards(self.numBlockCells.int) # shards per row after pass 1
    nCol = self.manifest.colShards(self.numBlockCells.int, self.numSlotBlocks.int)
      # shards per column after pass 2
    protectedCount = self.manifest.protectedBlocksCount
    parityPerSlot =
      self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)
    firstPassBlocks = self.manifest.firstPassParityBlocks(
      self.numBlockCells.int, self.numSlotBlocks.int
    )

  # 1. Data materialization: real blocks + zero-fill for pads
  let indices = ?self.slotIndices(slotIndex)
  var blocks = newSeq[seq[byte]](indices.len)
  for i, idx in indices:
    blocks[i] =
      if idx < protectedCount:
        let blk = ?await self.networkStore.getBlock(self.manifest.treeCid, idx)
        if blk.isEmpty:
          self.emptyBlock # erasure pad leaf: zero-fill, never fetched over the wire
        else:
          blk.data
      else:
        self.emptyBlock

  # 2. Pass 1 - row-wise: C data cells -> n_row shards; parity concatenated
  var pass1Cells: seq[byte]
  for b in 0 ..< T:
    var stripe: seq[seq[byte]]
    for c in 0 ..< C:
      stripe.add(blocks[b][c * cellSize ..< (c + 1) * cellSize])
    let parity = ?await self.erasure.encodeStripes(stripe, nRow - C)
    for shard in parity:
      pass1Cells.add(shard)

  # 3. Pass 2 - column-wise over ALL nRow cell-rows (data columns AND pass-1
  #    parity columns); parity concatenated column-major
  var pass2Cells: seq[byte]
  for j in 0 ..< nRow:
    var stripe: seq[seq[byte]]
    for b in 0 ..< T:
      let shard =
        if j < C:
          blocks[b][j * cellSize ..< (j + 1) * cellSize]
        else:
          let off = (b * (nRow - C) + (j - C)) * cellSize
          pass1Cells[off ..< off + cellSize]
      stripe.add(shard)
    let parity = ?await self.erasure.encodeStripes(stripe, nCol - T)
    for shard in parity:
      pass2Cells.add(shard)

  # 4. Pack into compound blocks and store at
  #    position(slotIndex, pass, i) under targetRoot
  let
    pass1Blocks = packParityCells(pass1Cells, cellSize, C)
    pass2Blocks = packParityCells(pass2Cells, cellSize, C)

  var
    items: seq[(bt.Block, Natural, ?PrometheiProof)]
    parityCids: seq[Cid]

  for i, data in pass1Blocks:
    let blk = ?bt.Block.new(data)
    parityCids.add(blk.cid)
    items.add(
      (
        blk,
        (protectedCount + slotIndex * parityPerSlot + i).Natural,
        PrometheiProof.none,
      )
    )

  for i, data in pass2Blocks:
    let blk = ?bt.Block.new(data)
    parityCids.add(blk.cid)
    items.add(
      (
        blk,
        (protectedCount + slotIndex * parityPerSlot + firstPassBlocks + i).Natural,
        PrometheiProof.none,
      )
    )

  ?await self.networkStore.putBlocks(targetRoot, items)
  success parityCids

func buildVerifyTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], slotRoots: openArray[SomeHash]
): ?!SomeTree =
  SomeTree.init(@slotRoots)

proc buildSlots*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], tp: Taskpool
): Future[?!void] {.async: (raises: [CancelledError]).} =
  ## Build all slot trees and the verifiable tree, and store them.
  ##
  ## Client-construction only: per-slot parity is encoded under a temporary
  ## overlay, slot trees are sealed as real overlays, and the verifiable sha
  ## tree over the protected leaves + per-slot parity leaves is finalized
  ## into the verifiable root (set on `self.verifiableRoot`).
  ##

  logScope:
    cid = self.manifest.treeCid
    blockCount = self.manifest.protectedBlocksCount

  trace "Building slots"

  if self.slotRoots.len == 0:
    let semaphore = newAsyncSemaphore(DefaultSlotBuildConcurrency)

    var created: seq[Cid]

    proc sealOne(
        slotIndex: Natural, tmpCid: Cid
    ): Future[?!SomeHash] {.async: (raises: [CancelledError]).} =
      ## Encode the slot's parity under the tmp overlay and seal the slot tree.
      await semaphore.acquire()
      try:
        discard ?await self.encodeSlot(slotIndex, tmpCid, tp)
        self.parityRoot = tmpCid.some
        success(?await self.sealSlot(slotIndex, self.manifest.treeCid, tmpCid, tp))
      finally:
        ?catch(semaphore.release())

    let buildRes = await self.repoStore.withTmpOverlay(
      body = proc(
          tmpCid: Cid
      ): Future[?!Cid] {.closure, gcsafe, async: (raises: [CancelledError]).} =
        let
          futures = collect(newSeq):
            for i in 0 ..< self.manifest.numSlots:
              sealOne(i.Natural, tmpCid)
          slotResults = await allFinished(futures)

        var slotRoots: seq[SomeHash]
        for i, fut in slotResults:
          if fut.failed:
            return failure(fut.error)
          let slotRes = ?catch(fut.read())
          if slotRes.isErr:
            return failure(slotRes.error)
          slotRoots.add(slotRes.get)

        for slotRoot in slotRoots:
          self.slotRoots.add(slotRoot)
          without slotCid =? slotRoot.toSlotCid, e:
            return failure(e)
          created.add(slotCid)

        without tree =? self.buildVerifyTree(self.slotRoots) and root =? tree.root, e:
          error "Failed to build slot roots tree", e = e.msg
          return failure(e)
        self.verifiableTree = some tree

        # verifiable sha tree over the protected leaves ++ per-slot parity leaves
        success(
          ?await self.erasure.treeAndProofs(
            ?await self.buildVerifiableLeafCids(), tmpCid
          )
        )
    )

    if buildRes.isErr:
      # drop created slot overlays (withTmpOverlay drops the tmp overlay itself)
      for c in created:
        if err =? (await self.repoStore.dropOverlay(c)).errorOption:
          error "Failed to drop slot overlay on failed build", c = c, err = err.msg
      return failure(buildRes.error)
    self.verifiableRoot = buildRes.get.some
  else:
    without tree =? self.buildVerifyTree(self.slotRoots) and root =? tree.root, e:
      error "Failed to build slot roots tree", e = e.msg
      return failure(e)

    if verifyTree =? self.verifyTree and verifyRoot =? verifyTree.root:
      if not bool(verifyRoot == root): # TODO: `!=` doesn't work for SecretBool
        return failure "Existing slots root doesn't match reconstructed root."

    self.verifiableTree = some tree

  success()

proc buildManifest*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], tp: Taskpool
): Future[?!Manifest] {.async: (raises: [CancelledError]).} =
  ## Build the manifest with the slot roots and the verifiable root and
  ## return it.
  ##

  ?await self.buildSlots(tp) # build the slots + verifiable root
  let rootCids = ?self.slotRoots.toSlotCids()
  without rootProvingCidRes =? self.verifyRoot .? toVerifyCid() and
    rootProvingCid =? rootProvingCidRes, e:
    error "Failed to map slot roots to CIDs", e = e.msg
    return failure(e)

  without verifiableRoot =? self.verifiableRoot, e:
    error "Verifiable root missing", e = e.msg
    return failure(e)

  let verifiableSize = (
    self.manifest.blockSize.int * (
      self.manifest.protectedBlocksCount +
      self.manifest.numSlots *
      self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)
    )
  ).NBytes

  Manifest.new(
    self.manifest, verifiableRoot, verifiableSize, rootProvingCid, rootCids,
    self.cellSize, self.strategy.strategyType,
  )

proc new*[SomeTree, SomeHash](
    _: type SlotsBuilder[SomeTree, SomeHash],
    networkStore: BlockStore,
    repoStore: RepoStore,
    erasure: Erasure,
    manifest: Manifest,
    strategy = LinearStrategy,
    cellSize = DefaultCellSize,
): ?!SlotsBuilder[SomeTree, SomeHash] =
  if not manifest.protected:
    trace "Manifest is not protected."
    return failure("Manifest is not protected.")

  logScope:
    blockSize = manifest.blockSize
    strategy = strategy
    cellSize = cellSize

  if (manifest.blocksCount mod manifest.numSlots) != 0:
    const msg = "Number of blocks must be divisible by number of slots."
    trace msg
    return failure(msg)

  let cellSize = if manifest.verifiable: manifest.cellSize else: cellSize
  if (manifest.blockSize mod cellSize) != 0.NBytes:
    const msg = "Block size must be divisible by cell size."
    trace msg
    return failure(msg)

  let
    numSlotBlocks = manifest.dataBlocksPerSlot
      # data-region blocks per slot (never manifest.numSlotBlocks - enlarged
      # physical count on verifiable manifests)
    numBlockCells = (manifest.blockSize div cellSize).int # number of cells per block
    numSlotCells = manifest.dataBlocksPerSlot * numBlockCells
      # number of uncorrected slot cells
    pow2SlotCells = nextPowerOfTwo(numSlotCells) # pow2 cells per slot
    numPadSlotBlocks = (pow2SlotCells div numBlockCells) - numSlotBlocks
      # pow2 blocks per slot

    numSlotBlocksTotal =
      # pad blocks per slot
      if numPadSlotBlocks > 0:
        numPadSlotBlocks + numSlotBlocks
      else:
        numSlotBlocks

    numBlocksTotal = numSlotBlocksTotal * manifest.numSlots # number of blocks per slot

    emptyBlock = newSeqWith(manifest.blockSize.int, 0xFF'u8)
    emptyDigestTree = ?SomeTree.digestTree(emptyBlock, cellSize.int)

    strategy =
      ?strategy.init(
        0,
        manifest.protectedBlocksCount - 1,
        manifest.numSlots,
        manifest.numSlots,
        numPadSlotBlocks,
      ).catch

  logScope:
    numSlotBlocks = numSlotBlocks
    numBlockCells = numBlockCells
    numSlotCells = numSlotCells
    pow2SlotCells = pow2SlotCells
    numPadSlotBlocks = numPadSlotBlocks
    numBlocksTotal = numBlocksTotal
    numSlotBlocksTotal = numSlotBlocksTotal
    strategy = strategy.strategyType

  trace "Creating slots builder"

  var self = SlotsBuilder[SomeTree, SomeHash](
    networkStore: networkStore,
    repoStore: repoStore,
    manifest: manifest,
    strategy: strategy,
    cellSize: cellSize,
    emptyBlock: emptyBlock,
    numSlotBlocks: numSlotBlocksTotal,
    emptyDigestTree: emptyDigestTree,
    erasure: erasure,
  )

  if manifest.verifiable:
    if manifest.slotRoots.len == 0 or manifest.slotRoots.len != manifest.numSlots:
      return failure "Manifest is verifiable but slot roots are missing or invalid."

    let
      slotRoots = manifest.slotRoots.mapIt((?it.fromSlotCid()))
      tree = ?self.buildVerifyTree(slotRoots)
      expectedRoot = ?manifest.verifyRoot.fromVerifyCid()
      verifyRoot = ?tree.root

    if verifyRoot != expectedRoot:
      return failure "Existing slots root doesn't match reconstructed root."

    self.slotRoots = slotRoots
    self.verifiableTree = some tree
    self.parityRoot = manifest.treeCid.some

  success self
