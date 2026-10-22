{.push raises: [].}

import std/sequtils
import std/tables

import pkg/iter
import pkg/libp2p
import pkg/chronos
import pkg/questionable
import pkg/questionable/results
import pkg/taskpools
import pkg/constantine/math/io/io_fields

import ../../utils/trackedfutures
import ../../logutils
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
import ./utils
import ./stripes

export converters, iter, asyncposeidon2

logScope:
  topics = "promethei slotsbuilder"

const
  DefaultSlotBuildConcurrency* = 4
  DefaultEncodeGroupCap* = 4

type SlotBuildControls* = object
  ## Resource bounds for one slot build. These control batching and
  ## admission only; encoding geometry comes from the manifest.
  encodeGroupCap*: int
  payloadIOTarget*: int
  proofMetadataTarget*: int

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
  controls: SlotBuildControls # bounded batching/admission controls
  verifiableRoot: ?Cid # verifiable sha root, set by buildSlots from the finalize res

func verifiable*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): bool {.inline.} =
  self.manifest.verifiable

func slotRoots*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): seq[SomeHash] {.inline.} =
  self.slotRoots

func verifyTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): ?SomeTree {.inline.} =
  self.verifiableTree

func verifyRoot*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): ?SomeHash {.inline.} =
  if tree =? self.verifyTree and root =? tree.root:
    return some root

func numSlots*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): Natural =
  self.manifest.numSlots

func numSlotBlocks*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  self.numSlotBlocks

func verifiableRoot*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): ?Cid =
  self.verifiableRoot

func numBlocks*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): Natural =
  self.numSlotBlocks * self.manifest.numSlots

func numBlockCells*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  (self.manifest.blockSize div self.cellSize).Natural

func parityBlocksPerSlot*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural {.inline.} =
  self.manifest.parityBlocksPerSlot(self.numBlockCells.int, self.numSlotBlocks.int)

func cellSize*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): NBytes =
  self.cellSize

func numSlotCells*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash]
): Natural =
  ## Number of cells per slot - the FULL sampling space (data, pad, and
  ## parity leaves)
  ##

  self.numBlockCells * (self.numSlotBlocks + self.parityBlocksPerSlot)

func slotIndices*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], slot: Natural
): ?!seq[int] =
  success toSeq(?catch(self.strategy.getIndices(slot)))

func manifest*[SomeTree, SomeHash](self: SlotsBuilder[SomeTree, SomeHash]): Manifest =
  self.manifest

proc buildBlockTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], root: Cid, blkIdx: Natural, slotPos: Natural
): Future[?!(seq[byte], SomeTree)] {.async: (raises: [CancelledError]).} =
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
  return await self.repoStore.getCid(root, index)

proc buildVerifiableLeafCids*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], parityRoot: Cid
): Future[?!ref seq[Cid]] {.async: (raises: [CancelledError]).} =
  let
    protectedCount = self.manifest.protectedBlocksCount
    parityPerSlot = self.parityBlocksPerSlot

  var leafCids = newSeq[Cid](protectedCount + self.manifest.numSlots * parityPerSlot)
  for idx in 0 ..< protectedCount:
    leafCids[idx] = ?await self.getStoredCid(self.manifest.treeCid, idx.Natural)

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
    for slotPosition, blockIndex in ?catch(self.strategy.getIndices(slotIndex)):
      logScope:
        blkIdx = blockIndex
        pos = slotPosition

      trace "Getting block CID for tree at index"
      let
        (_, tree) =
          ?await self.buildBlockTree(self.manifest.treeCid, blockIndex, slotPosition)
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
  if slotPos < self.numSlotBlocks:
    let indices = ?self.slotIndices(slotIndex)
    success(?await self.buildBlockTree(dataRoot, indices[slotPos], slotPos))
  else:
    let
      protectedCount = self.manifest.protectedBlocksCount
      parityPerSlot = self.parityBlocksPerSlot
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
  let
    dataLeaves = self.numSlotBlocks
    parityLeaves = self.parityBlocksPerSlot

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
  logScope:
    dataRoot = dataRoot
    parityRoot = parityRoot
    slotIndex = slotIndex

  trace "Sealing slot tree"

  without tree =? (await self.buildSlotTree(slotIndex, dataRoot, parityRoot, tp)) and
    treeCid =? tree.root .? toSlotCid, e:
    error "Failed to build slot tree", e = e.msg
    return failure(e)

  # A verifiable manifest already commits to this slot's root: compare before
  # persisting anything (the client build seals an uncommitted protected
  # manifest and has nothing to compare yet).
  if self.manifest.verifiable and treeCid != self.manifest.slotRoots[slotIndex]:
    error "Slot root mismatch",
      manifest = self.manifest.slotRoots[slotIndex], recovered = treeCid
    return failure(newException(PrometheiError, "Slot root mismatch"))

  let
    indices = toSeq(?catch(self.strategy.getIndices(slotIndex)))
    dataLeaves = indices.len
    parityLeaves = self.parityBlocksPerSlot
    protectedCount = self.manifest.protectedBlocksCount

  trace "Storing slot tree", treeCid, slotIndex, leaves = tree.leavesCount
  ?await self.repoStore.withOverlay(
    treeCid,
    status = Storing.some,
    body = proc(): Future[?!void] {.closure, async: (raises: [CancelledError]).} =
      var
        proofItems: seq[(Natural, Cid, Cid, PrometheiProof)]
        proofBytes = 0

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
            ?await self.getStoredCid(
              parityRoot,
              (protectedCount + slotIndex.int * parityLeaves + (pos - dataLeaves)).Natural,
            )

        let recordBytes = proofRecordBytes(cellCid, encodableProof)
        if proofItems.len > 0 and
            proofBytes + recordBytes > self.controls.proofMetadataTarget:
          ?await self.repoStore.putCellCidsAndProofs(treeCid, proofItems)
          proofItems.setLen(0)
          proofBytes = 0

        proofItems.add((pos.Natural, cellCid, blkCid, encodableProof))
        proofBytes += recordBytes

      ?await self.repoStore.putCellCidsAndProofs(treeCid, proofItems)
      success(),
  )

  tree.root()

proc encodePassInner(
    stripes: Iter[Future[?!Stripe]],
    erasure: Erasure,
    parityCount: Natural,
    encodeGroupCap: int,
    store: BlockStore,
    root: Cid,
    cellSize, cellsPerBlock, payloadTarget: int,
    startIndex: Natural,
    expectedBlocks: int,
): Future[?!seq[tuple[index: Natural, cid: Cid]]] {.async: (raises: [CancelledError]).} =
  let blockBytes = cellsPerBlock * cellSize

  type BlockBuffer = tuple[buffer: seq[byte], len: int]

  var
    blocksBuffer: Table[Natural, BlockBuffer]
    items: seq[(bt.Block, Natural, ?PrometheiProof)]
    batchBytes: int
    cids: seq[tuple[index: Natural, cid: Cid]]

  proc flush(): Future[?!void] {.async: (raises: [CancelledError]).} =
    if items.len == 0:
      return success()

    var batch = move items
    items = @[]
    batchBytes = 0
    ?await store.putBlocks(root, batch)

    success()

  proc appendBlock(blk: bt.Block, blockIndex: int) =
    items.add((blk, blockIndex.Natural, PrometheiProof.none))
    cids.add (index: blockIndex.Natural, cid: blk.cid)

  proc addCell(
      cell: seq[byte], cellIndex, stripeIndex: int
  ): Future[?!void] {.async: (raises: [CancelledError]).} =
    if cell.len != cellSize:
      return failure(
        newException(PrometheiError, "Parity cell length does not match cellSize")
      )

    let
      parityCellOrdinal = stripeIndex * parityCount.int + cellIndex
      blockIndex = startIndex + Natural(parityCellOrdinal div cellsPerBlock)
      blockOffset = (parityCellOrdinal mod cellsPerBlock) * cellSize

    var blockBuffPtr: ptr BlockBuffer
    blocksBuffer.withValue(blockIndex, blockBuff):
      blockBuffPtr = blockBuff
    do:
      blockBuffPtr =
        addr blocksBuffer.mgetOrPut(blockIndex, (newSeqWith(blockBytes, 0'u8), 0))

    copyMem(addr blockBuffPtr[].buffer[blockOffset], unsafeAddr cell[0], cellSize)
    blockBuffPtr[].len += cellSize

    if blockBuffPtr[].len == blockBytes:
      let blk = ?bt.Block.new(move blockBuffPtr[].buffer)
      blocksBuffer.del(blockIndex)
      appendBlock(blk, blockIndex)
      batchBytes += blockBytes
      if batchBytes >= payloadTarget:
        ?await flush()

    success()

  proc encodeDispatcher(
      fetchFut: Future[?!Stripe], stripeIndex: int
  ): Future[?!void] {.async: (raises: [CancelledError]).} =
    var stripe = ?catchAsync(?await fetchFut)
    let encoded = ?await erasure.encodeStripes(move stripe, parityCount)
    for cellIndex, cell in encoded:
      ?await addCell(cell, cellIndex, stripeIndex)

    success()

  var
    dispatchJobs: seq[Future[?!void]]
    stripeIndex: int

  defer:
    for job in dispatchJobs:
      if not job.finished:
        await noCancel job.cancelAndWait()

  while not stripes.finished:
    try:
      if dispatchJobs.len >= encodeGroupCap:
        let
          jobFut = ?catchAsync(await one(dispatchJobs))
          idx = dispatchJobs.find(jobFut)

        if idx < 0:
          trace "Invalid index awaiting dispatch jobs", idx
          return failure("Invalid index awaiting dispatch jobs")

        ?catchAsync(?await jobFut)
        dispatchJobs.del(idx)

        if stripes.finished:
          break

      dispatchJobs.add encodeDispatcher(?catch(stripes.next()), stripeIndex)
      stripeIndex.inc
    except CancelledError as exc:
      trace "Stripes dispatch loop cancelled", exc = exc.msg
      await noCancel allFutures(dispatchJobs.mapIt(it.cancelAndWait()))
      raise exc

  await allFutures(dispatchJobs)
  for job in dispatchJobs:
    ?catchAsync(?await job)

  let
    totalCells = stripeIndex * parityCount.int
    remainingBytes = (totalCells mod cellsPerBlock) * cellSize

  if remainingBytes > 0:
    let finalIndex = startIndex + Natural(totalCells div cellsPerBlock)
    blocksBuffer.withValue(finalIndex, blockBuff):
      if blockBuff[].len != remainingBytes:
        return
          failure(newException(PrometheiError, "Unexpected final parity block length"))
      let blk = ?bt.Block.new(move blockBuff[].buffer)
      appendBlock(blk, finalIndex)
      batchBytes += blockBytes
    do:
      return failure(newException(PrometheiError, "Missing final parity block"))
    blocksBuffer.del(finalIndex)

  if blocksBuffer.len != 0:
    return failure(newException(PrometheiError, "Incomplete parity blocks"))

  ?await flush()

  if cids.len != expectedBlocks:
    return failure(
      newException(
        PrometheiError,
        "Unexpected parity block count: " & $cids.len & ", expected " & $expectedBlocks,
      )
    )

  success(move cids)

proc encodePass(
    stripes: Iter[Future[?!Stripe]],
    erasure: Erasure,
    parityCount: Natural,
    encodeGroupCap: int,
    store: BlockStore,
    root: Cid,
    cellSize, cellsPerBlock, payloadTarget: int,
    startIndex: Natural,
    expectedBlocks: int,
): Future[?!seq[tuple[index: Natural, cid: Cid]]] {.async: (raises: [CancelledError]).} =
  try:
    let
      res = await encodePassInner(
        stripes, erasure, parityCount, encodeGroupCap, store, root, cellSize,
        cellsPerBlock, payloadTarget, startIndex, expectedBlocks,
      )
      disposed = catch(stripes.dispose())

    if err =? res.errorOption:
      if disposeErr =? disposed.errorOption:
        warn "Failed to dispose stripe iterator", err = disposeErr.msg
      return failure(err)

    if err =? disposed.errorOption:
      return failure(err)

    res
  except CancelledError as exc:
    let disposed = catch(stripes.dispose())
    if disposeErr =? disposed.errorOption:
      warn "Failed to dispose stripe iterator", err = disposeErr.msg
    raise exc

proc encodeSlot*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash],
    slotIndex: Natural,
    targetRoot: Cid,
    tp: Taskpool,
): Future[?!seq[tuple[index: Natural, cid: Cid]]] {.async: (raises: [CancelledError]).} =
  logScope:
    targetRoot = targetRoot
    slotIndex = slotIndex

  trace "Encoding slot parity"
  let
    cellSize = self.cellSize.int
    cellsPerBlock = self.numBlockCells.int
    numSlotBlocks = self.numSlotBlocks.int
    protectedCount = self.manifest.protectedBlocksCount
    parityPerSlot = self.parityBlocksPerSlot
    firstPassBlocks = self.manifest.firstPassParityBlocks(cellsPerBlock, numSlotBlocks)
    secondPassBlocks =
      self.manifest.secondPassParityBlocks(cellsPerBlock, numSlotBlocks)
    pass1Start = (protectedCount + slotIndex.int * parityPerSlot).Natural
    rowParity = (self.manifest.rowShards(cellsPerBlock) - cellsPerBlock).Natural
    columnParity =
      (self.manifest.colShards(cellsPerBlock, numSlotBlocks) - numSlotBlocks).Natural
    pass2Start = (pass1Start.int + firstPassBlocks).Natural
    rowIterator =
      ?rowStripes(
        self.networkStore, self.manifest, self.strategy, slotIndex, self.cellSize,
        self.controls.payloadIOTarget,
      )

  defer:
    rowIterator.dispose()

  let columnIterator =
    ?columnStripes(
      self.networkStore, self.repoStore, self.manifest, self.strategy, slotIndex,
      targetRoot, self.cellSize, self.controls.payloadIOTarget,
    )

  defer:
    columnIterator.dispose()

  var cids: seq[tuple[index: Natural, cid: Cid]]
  for (stripes, parityCount, startIndex, expectedBlocks) in [
    (rowIterator, rowParity, pass1Start, firstPassBlocks),
    (columnIterator, columnParity, pass2Start, secondPassBlocks),
  ]:
    let passCids =
      ?await encodePass(
        stripes, self.erasure, parityCount, self.controls.encodeGroupCap,
        self.networkStore, targetRoot, cellSize, cellsPerBlock,
        self.controls.payloadIOTarget, startIndex, expectedBlocks,
      )
    cids.add passCids

  success(move cids)

func buildVerifyTree*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], slotRoots: openArray[SomeHash]
): ?!SomeTree =
  SomeTree.init(@slotRoots)

proc buildSlots*[SomeTree, SomeHash](
    self: SlotsBuilder[SomeTree, SomeHash], tp: Taskpool
): Future[?!void] {.async: (raises: [CancelledError]).} =
  logScope:
    cid = self.manifest.treeCid
    blockCount = self.manifest.protectedBlocksCount

  trace "Building slots"

  if self.slotRoots.len == 0:
    let semaphore = newAsyncSemaphore(DefaultSlotBuildConcurrency)

    proc sealOne(
        slotIndex: Natural, root: Cid
    ): Future[?!SomeHash] {.async: (raises: [CancelledError]).} =
      await semaphore.acquire()
      try:
        success(?await self.sealSlot(slotIndex, root, root, tp))
      finally:
        ?catch(semaphore.release())

    # The temporary overlay is finalized by this call, so `R_v` survives any
    # later failure; no slot tree is written before it returns.
    let shaRoot =
      ?await self.repoStore.withTmpOverlay(
        body = proc(
            tmpCid: Cid
        ): Future[?!Cid] {.closure, gcsafe, async: (raises: [CancelledError]).} =
          for slotNumber in 0 ..< self.manifest.numSlots:
            discard ?await self.encodeSlot(slotNumber.Natural, tmpCid, tp)

          # verifiable sha tree over the protected leaves ++ per-slot parity leaves
          success(
            ?await self.erasure.treeAndProofs(
              ?await self.buildVerifiableLeafCids(tmpCid),
              tmpCid,
              self.manifest.blockSize,
              self.controls.payloadIOTarget,
              self.controls.proofMetadataTarget,
            )
          )
      )

    var sealFutures: seq[Future[?!SomeHash]]
    for slotNumber in 0 ..< self.manifest.numSlots:
      sealFutures.add(sealOne(slotNumber.Natural, shaRoot))

    ?await settleSlotFutures(sealFutures)
    var roots: seq[SomeHash]
    for future in sealFutures:
      roots.add future.value.get()

    without tree =? self.buildVerifyTree(roots) and root =? tree.root, e:
      error "Failed to build slot roots tree", e = e.msg
      return failure(e)

    self.slotRoots = roots
    self.verifiableTree = some tree
    self.verifiableRoot = shaRoot.some
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
  ?await self.buildSlots(tp)
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
      self.manifest.numSlots * self.parityBlocksPerSlot
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
    controls = SlotBuildControls(
      encodeGroupCap: DefaultEncodeGroupCap,
      payloadIOTarget: DefaultPayloadIOTarget,
      proofMetadataTarget: DefaultProofMetadataTarget,
    ),
): ?!SlotsBuilder[SomeTree, SomeHash] =
  if controls.encodeGroupCap <= 0 or controls.payloadIOTarget <= 0 or
      controls.proofMetadataTarget <= 0:
    return failure("Slot build controls must be positive.")

  if not manifest.protected:
    trace "Manifest is not protected."
    return failure("Manifest is not protected.")

  ?manifest.verify()

  let effectiveCellSize = if manifest.verifiable: manifest.cellSize else: cellSize
  if effectiveCellSize <= 0.NBytes:
    return failure("Cell size must be positive.")
  if (manifest.blockSize mod effectiveCellSize) != 0.NBytes:
    const msg = "Block size must be divisible by cell size."
    trace msg
    return failure(msg)

  if (manifest.blocksCount mod manifest.numSlots) != 0:
    const msg = "Number of blocks must be divisible by number of slots."
    trace msg
    return failure(msg)

  logScope:
    blockSize = manifest.blockSize
    strategy = strategy
    cellSize = effectiveCellSize

  let
    numSlotBlocks = manifest.dataBlocksPerSlot
      # data-region blocks per slot (never manifest.numSlotBlocks - enlarged
      # physical count on verifiable manifests)
    numBlockCells = (manifest.blockSize div effectiveCellSize).int
      # number of cells per block
    numPadSlotBlocks = manifest.numPadSlotBlocks
      # one shared rate-aware rule for manifest geometry and strategy setup
    numSlotBlocksTotal = manifest.numSlotBlocksTotal
    numBlocksTotal = numSlotBlocksTotal * manifest.numSlots # number of blocks per slot

  if numBlockCells <= 0 or numBlockCells > MaxBlockCells or
      (numBlockCells and (numBlockCells - 1)) != 0:
    return failure "Cells per block must be a positive power of two."

  if numSlotBlocksTotal <= 0 or numSlotBlocksTotal > MaxSlotBlocks or
      numPadSlotBlocks < 0 or (numSlotBlocksTotal and (numSlotBlocksTotal - 1)) != 0:
    return failure "Slot geometry is not a supported power-of-two grid."

  let
    innerK = manifest.innerK
    innerN = manifest.innerN

  if innerK <= 0 or innerN <= innerK or (numBlockCells * innerN) mod innerK != 0 or
      (numSlotBlocksTotal * innerN) mod innerK != 0:
    return failure "Inner code rate is not supported."

  if effectiveCellSize.int mod 64 != 0:
    return failure "Cell size must be a multiple of 64 bytes."

  if innerN - innerK > innerK:
    return failure "Too many inner parity shards."

  if manifest.rowShards(numBlockCells) > MaxInnerShards or
      manifest.colShards(numBlockCells, numSlotBlocksTotal) > MaxInnerShards:
    return failure "Inner shard count exceeds the encoder limit."

  if numSlotBlocksTotal < innerK:
    return failure "Padded slot geometry is not supported."

  let
    parityBlocks = manifest.parityBlocksPerSlot(numBlockCells, numSlotBlocksTotal)
    sampleCells = (numSlotBlocksTotal + parityBlocks) * numBlockCells

  if sampleCells <= 0 or sampleCells > (1 shl 32):
    return failure "Slot sampling space is not supported."

  let
    emptyBlock = newSeqWith(manifest.blockSize.int, 0xFF'u8)
    emptyDigestTree = ?SomeTree.digestTree(emptyBlock, effectiveCellSize.int)

  let strategy =
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
    cellSize: effectiveCellSize,
    emptyBlock: emptyBlock,
    numSlotBlocks: numSlotBlocksTotal,
    emptyDigestTree: emptyDigestTree,
    erasure: erasure,
    controls: controls,
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

  success self
