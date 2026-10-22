{.push raises: [].}

import std/sequtils
import std/tables

import pkg/iter
import pkg/chronos
import pkg/libp2p
import pkg/questionable/results

import ../../blocktype as bt
import ../../errors
import ../../indexingstrategy
import ../../manifest
import ../../stores

type
  Stripe* = seq[seq[byte]]

  CellPlacement = object
    blockIndex: Natural
    cellOffset: int

  StripeLayout = object
    inputRowCount: int
    rowParityCellsPerRow: int
    cellsPerBlock: int
    cellBytes: int
    blockBytes: int
    protectedCount: int
    parityBase: Natural
    slotIndices: seq[int]
    readBatchCap: int

func missingSourceBlock(treeCid: Cid, index: Natural): ref CatchableError =
  newException(
    BlockNotFoundError,
    "Required block missing from batch response, treeCid: " & $treeCid & ", index: " &
      $index,
  )

func invalidSourceBlock(index: Natural): ref CatchableError =
  newException(
    PrometheiError, "Block length does not match manifest blockSize, idx: " & $index
  )

func invalidParityBlock(treeCid: Cid, index: Natural): ref CatchableError =
  newException(
    PrometheiError,
    "Invalid first-pass parity block, treeCid: " & $treeCid & ", index: " & $index,
  )

proc readBatchMap(
    store: BlockStore, root: Cid, indices: seq[Natural]
): Future[?!Table[Natural, bt.Block]] {.async: (raises: [CancelledError]).} =
  ## Match batch responses by logical index and reject omissions; response
  ## order is not guaranteed and a partial success is not valid input.
  var blocks = initTable[Natural, bt.Block]()
  if indices.len == 0:
    return success(blocks)

  let response = ?await store.getBlocks(root, indices)
  for (index, blk) in response:
    blocks[index] = blk

  for index in indices:
    if index notin blocks:
      return failure(missingSourceBlock(root, index))

  success blocks

func stripeLayout(
    manifest: Manifest,
    slotStrategy: IndexingStrategy,
    slotIndex: Natural,
    effectiveCellSize: NBytes,
    payloadIOTarget: int,
): ?!StripeLayout =
  if not manifest.protected:
    return failure("Manifest is not protected.")
  ?manifest.verify()

  let
    cellBytes = effectiveCellSize.int
    blockBytes = manifest.blockSize.int

  if cellBytes <= 0:
    return failure("Cell size must be positive.")

  if blockBytes <= 0 or blockBytes mod cellBytes != 0:
    return failure("Block size must be divisible by cell size.")

  let cellsPerBlock = blockBytes div cellBytes

  let
    inputRowCount = manifest.numSlotBlocksTotal
    rowParityCellsPerRow = manifest.rowShards(cellsPerBlock) - cellsPerBlock
    protectedCount = manifest.protectedBlocksCount
    parityPerSlot = manifest.parityBlocksPerSlot(cellsPerBlock, inputRowCount)

  if inputRowCount > high(int) div cellsPerBlock:
    return failure("Stripe cell count is not representable.")

  if slotIndex.int > (high(int) - protectedCount) div parityPerSlot:
    return failure("Parity base is not representable.")

  let parityBase = protectedCount + slotIndex.int * parityPerSlot

  let slotIndices = ?catch(toSeq(slotStrategy.getIndices(slotIndex)))
  if slotIndices.len != inputRowCount:
    return failure("Slot source index count does not match slot geometry.")

  success(
    StripeLayout(
      inputRowCount: inputRowCount,
      rowParityCellsPerRow: rowParityCellsPerRow,
      cellsPerBlock: cellsPerBlock,
      cellBytes: cellBytes,
      blockBytes: blockBytes,
      protectedCount: protectedCount,
      parityBase: parityBase.Natural,
      slotIndices: slotIndices,
      readBatchCap: max(1, payloadIOTarget div blockBytes),
    )
  )

proc buildStripe(
    store: BlockStore,
    root: Cid,
    layout: StripeLayout,
    selectedCells: Iter[int],
    expectedCells: int,
    parityColumns: bool,
): Future[?!Stripe] {.async: (raises: [CancelledError]).} =
  var
    stripe: Stripe
    placements: seq[CellPlacement]
    requestedIndices: seq[Natural]

  proc flushBatch(): Future[?!void] {.async: (raises: [CancelledError]).} =
    let blocks = ?await readBatchMap(store, root, requestedIndices)

    for placement in placements:
      if not parityColumns and placement.blockIndex >= layout.protectedCount.Natural:
        stripe.add newSeqWith(layout.cellBytes, 0xFF'u8)
        continue

      let blk = blocks.getOrDefault(placement.blockIndex)
      if blk.isNil:
        return failure(missingSourceBlock(root, placement.blockIndex))

      if blk.isEmpty:
        if parityColumns:
          return failure(invalidParityBlock(root, placement.blockIndex))

        stripe.add newSeqWith(layout.cellBytes, 0xFF'u8)
        continue

      if blk.data.len != layout.blockBytes:
        if parityColumns:
          return failure(invalidParityBlock(root, placement.blockIndex))
        return failure(invalidSourceBlock(placement.blockIndex))

      var cell = newSeq[byte](layout.cellBytes)
      copyMem(
        addr cell[0],
        unsafeAddr blk.data[placement.cellOffset * layout.cellBytes],
        layout.cellBytes,
      )

      stripe.add move cell

    placements.setLen(0)
    requestedIndices.setLen(0)
    success()

  for cellIndex in selectedCells:
    let
      sourceOrdinal = cellIndex div layout.cellsPerBlock
      cellOffset = cellIndex mod layout.cellsPerBlock

    let blockIndex =
      if parityColumns:
        if sourceOrdinal.Natural > high(Natural) - layout.parityBase:
          return failure("First-pass parity block index is out of range.")

        layout.parityBase + sourceOrdinal.Natural
      else:
        if sourceOrdinal >= layout.slotIndices.len:
          return failure("Stripe source ordinal is out of range.")

        layout.slotIndices[sourceOrdinal].Natural

    let needsBlock =
      (parityColumns or blockIndex < layout.protectedCount.Natural) and
      blockIndex notin requestedIndices

    if needsBlock and requestedIndices.len >= layout.readBatchCap:
      ?await flushBatch()

    placements.add CellPlacement(blockIndex: blockIndex, cellOffset: cellOffset)
    if needsBlock:
      requestedIndices.add blockIndex

  ?await flushBatch()

  if stripe.len != expectedCells:
    return failure("Stripe selection does not match expected cell count.")

  success move stripe

proc selectedStripe(
    indexSelection: IndexingStrategy,
    stripeIndex: int,
    store: BlockStore,
    root: Cid,
    layout: StripeLayout,
    expectedCells: int,
    parityColumns: bool,
): Future[?!Stripe] {.async: (raises: [CancelledError]).} =
  let selectedCells = ?catch(indexSelection.getIndices(stripeIndex))
  defer:
    selectedCells.dispose()
  await buildStripe(store, root, layout, selectedCells, expectedCells, parityColumns)

proc rowStripes*(
    sourceStore: BlockStore,
    manifest: Manifest,
    slotStrategy: IndexingStrategy,
    slotIndex: Natural,
    effectiveCellSize: NBytes,
    payloadIOTarget: int,
): ?!Iter[Future[?!Stripe]] =
  let
    layout =
      ?stripeLayout(
        manifest, slotStrategy, slotIndex, effectiveCellSize, payloadIOTarget
      )
    rowSelection =
      ?catch(
        LinearStrategy.init(
          0, layout.inputRowCount * layout.cellsPerBlock - 1, layout.inputRowCount
        )
      )
    ordinals = Iter[int].new(0 ..< layout.inputRowCount)
    stripes = Iter[Future[?!Stripe]].new(
      genNext = proc(): Future[?!Stripe] {.raises: [CatchableError].} =
        selectedStripe(
          rowSelection,
          ordinals.next(),
          sourceStore,
          manifest.treeCid,
          layout,
          layout.cellsPerBlock,
          false,
        ),
      isFinished = proc(): bool =
        ordinals.finished,
      dispose = proc() =
        ordinals.dispose(),
      isDisposed = proc(): bool =
        ordinals.disposed,
    )

  success(stripes)

proc columnStripes*(
    sourceStore: BlockStore,
    localParityStore: BlockStore,
    manifest: Manifest,
    slotStrategy: IndexingStrategy,
    slotIndex: Natural,
    parityRoot: Cid,
    effectiveCellSize: NBytes,
    payloadIOTarget: int,
): ?!Iter[Future[?!Stripe]] =
  let layout =
    ?stripeLayout(manifest, slotStrategy, slotIndex, effectiveCellSize, payloadIOTarget)
  if layout.inputRowCount > high(int) div layout.rowParityCellsPerRow:
    return failure("Parity column selection range is not representable.")

  let
    dataColumnSelection =
      ?catch(
        SteppedStrategy.init(
          0, layout.inputRowCount * layout.cellsPerBlock - 1, layout.cellsPerBlock
        )
      )
    parityColumnSelection =
      ?catch(
        SteppedStrategy.init(
          0,
          layout.inputRowCount * layout.rowParityCellsPerRow - 1,
          layout.rowParityCellsPerRow,
        )
      )
    ordinals = Iter[int].new(0 ..< (layout.cellsPerBlock + layout.rowParityCellsPerRow))
    stripes = Iter[Future[?!Stripe]].new(
      genNext = proc(): Future[?!Stripe] {.raises: [CatchableError].} =
        let columnIndex = ordinals.next()
        if columnIndex < layout.cellsPerBlock:
          selectedStripe(
            dataColumnSelection, columnIndex, sourceStore, manifest.treeCid, layout,
            layout.inputRowCount, false,
          )
        else:
          selectedStripe(
            parityColumnSelection,
            columnIndex - layout.cellsPerBlock,
            localParityStore,
            parityRoot,
            layout,
            layout.inputRowCount,
            true,
          ),
      isFinished = proc(): bool =
        ordinals.finished,
      dispose = proc() =
        ordinals.dispose(),
      isDisposed = proc(): bool =
        ordinals.disposed,
    )

  success(stripes)
