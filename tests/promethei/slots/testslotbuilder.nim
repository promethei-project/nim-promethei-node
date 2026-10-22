import std/algorithm
import std/atomics
import std/math
import std/os
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
import pkg/promethei/slots/builder/stripes
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

proc newTestBuilderWithControls(
    store: RepoStore,
    manifest: Manifest,
    tp: Taskpool,
    cellSize: NBytes,
    controls: SlotBuildControls,
): Poseidon2Builder =
  Poseidon2Builder.new(
    store,
    store,
    Erasure.new(store, store, leoEncoderProvider, leoDecoderProvider, tp),
    manifest,
    cellSize = cellSize,
    controls = controls,
  ).tryGet

proc deterministicBlock(index, blockSize: int): bt.Block =
  var data = newSeq[byte](blockSize)
  for byteIndex in 0 ..< data.len:
    data[byteIndex] =
      byte((index * 37 + byteIndex * 11 + (byteIndex div 64) * 3) and 0xFF)
  bt.Block.new(data).tryGet

proc deterministicDataset(blockSize, count: int): seq[bt.Block] =
  ## Deterministic payloads for cross-run parity vectors.
  collect(newSeq):
    for blockIndex in 0 ..< count:
      deterministicBlock(blockIndex, blockSize)

proc inIndexOrder(
    entries: openArray[tuple[index: Natural, cid: Cid]]
): seq[tuple[index: Natural, cid: Cid]] =
  var ordered = @entries
  ordered.sort do(a, b: tuple[index: Natural, cid: Cid]) -> int:
    cmp(a.index, b.index)
  ordered

type RecordingStore = ref object of BlockStore
  ## Records the item count of every parity write batch.
  inner: BlockStore
  writeBatchSizes: seq[int]
  readBatchSizes: seq[int]
  activeReads: int
  peakReads: int

method getBlocks*(
    self: RecordingStore, treeCid: Cid, indices: seq[Natural]
): Future[?!seq[(Natural, bt.Block)]] {.async: (raises: [CancelledError]), gcsafe.} =
  inc self.activeReads
  self.peakReads = max(self.peakReads, self.activeReads)
  defer:
    dec self.activeReads
  self.readBatchSizes.add indices.len
  await self.inner.getBlocks(treeCid, indices)

method putBlocks*(
    self: RecordingStore, treeCid: Cid, items: seq[(bt.Block, Natural, ?PrometheiProof)]
): Future[?!void] {.async: (raises: [CancelledError]).} =
  self.writeBatchSizes.add items.len
  await self.inner.putBlocks(treeCid, items)

type CancelFirstReadStore = ref object of BlockStore
  ## Returns an already-cancelled read future on the first batch.
  inner: BlockStore
  cancelled = false

method getBlocks*(
    self: CancelFirstReadStore, treeCid: Cid, indices: seq[Natural]
): Future[?!seq[(Natural, bt.Block)]] {.async: (raises: [CancelledError]), gcsafe.} =
  if not self.cancelled:
    self.cancelled = true
    raise newException(CancelledError, "cancelled stripe read")
  await self.inner.getBlocks(treeCid, indices)

method putBlocks*(
    self: CancelFirstReadStore,
    treeCid: Cid,
    items: seq[(bt.Block, Natural, ?PrometheiProof)],
): Future[?!void] {.async: (raises: [CancelledError]).} =
  await self.inner.putBlocks(treeCid, items)

var
  firstEncodeCount: Atomic[int]
  firstEncodeStarted: Atomic[bool]
  firstEncodeFinished: Atomic[bool]
  activeEncodes: Atomic[int]
  peakEncodes: Atomic[int]
  gatedEncodeOrdinal: Atomic[int]
  releaseGatedEncode: Atomic[bool]
  gatedEncodeStarted: Atomic[bool]

type
  ReadStartStore = ref object of BlockStore
    inner: BlockStore
    readStarts: AsyncQueue[int]
    readIndex: int
    secondReadBeforeEncodeFinished: bool

  SlowEncoderBackend = ref object of EncoderBackend
    inner: EncoderBackend

  FailReadStore = ref object of BlockStore
    inner: BlockStore
    readIndex: int
    readFailureEmitted: bool

method getBlocks*(
    self: ReadStartStore, treeCid: Cid, indices: seq[Natural]
): Future[?!seq[(Natural, bt.Block)]] {.async: (raises: [CancelledError]).} =
  let index = self.readIndex
  inc self.readIndex
  if index == 1:
    while not firstEncodeStarted.load():
      await sleepAsync(1.milliseconds)
    self.secondReadBeforeEncodeFinished = not firstEncodeFinished.load()
  await self.readStarts.put(index)
  await self.inner.getBlocks(treeCid, indices)

method putBlocks*(
    self: ReadStartStore, treeCid: Cid, items: seq[(bt.Block, Natural, ?PrometheiProof)]
): Future[?!void] {.async: (raises: [CancelledError]).} =
  await self.inner.putBlocks(treeCid, items)

method getBlocks*(
    self: FailReadStore, treeCid: Cid, indices: seq[Natural]
): Future[?!seq[(Natural, bt.Block)]] {.async: (raises: [CancelledError]).} =
  inc self.readIndex
  if self.readIndex == 2:
    while not firstEncodeStarted.load():
      await sleepAsync(1.milliseconds)
    self.readFailureEmitted = true
    return failure(newException(BlockNotFoundError, "forced read failure"))
  await self.inner.getBlocks(treeCid, indices)

method putBlocks*(
    self: FailReadStore, treeCid: Cid, items: seq[(bt.Block, Natural, ?PrometheiProof)]
): Future[?!void] {.async: (raises: [CancelledError]).} =
  await self.inner.putBlocks(treeCid, items)

method encode*(
    self: SlowEncoderBackend, buffers, parity: var seq[seq[byte]]
): Result[void, cstring] {.gcsafe.} =
  let
    invocationOrdinal = firstEncodeCount.fetchAdd(1)
    active = activeEncodes.fetchAdd(1) + 1

  var observedPeak = peakEncodes.load()
  while active > observedPeak and not peakEncodes.compareExchange(observedPeak, active):
    discard

  defer:
    discard activeEncodes.fetchSub(1)

  if invocationOrdinal == 0:
    firstEncodeStarted.store(true)

  if invocationOrdinal == gatedEncodeOrdinal.load():
    gatedEncodeStarted.store(true)
    while not releaseGatedEncode.load():
      sleep(1)

  let res = self.inner.encode(buffers, parity)
  if invocationOrdinal == 0:
    firstEncodeFinished.store(true)
  res

method release*(self: SlowEncoderBackend) {.gcsafe.} =
  self.inner.release()

proc slowEncoderProvider(
    size, blocks, parity: int
): EncoderBackend {.raises: [Defect], noSideEffect, nimcall.} =
  SlowEncoderBackend(inner: leoEncoderProvider(size, blocks, parity))

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
    numSlotBlocksTotal = max(nextPowerOfTwo(numSlotBlocks), InnerCodeK.int)
    numPadSlotBlocks = numSlotBlocksTotal - numSlotBlocks
    numBlocksTotal = numSlotBlocksTotal * numSlots

    nRow = numBlockCells * InnerCodeN.int div InnerCodeK.int
    nCol = numSlotBlocksTotal * InnerCodeN.int div InnerCodeK.int
    parityPerSlot =
      divUp(numSlotBlocksTotal * (nRow - numBlockCells), numBlockCells) +
      divUp(nRow * (nCol - numSlotBlocksTotal), numBlockCells)

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

  test "Rejects an inconsistent protected block count":
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
        "Broken manifest: wrong originalBlocksCount"

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

  test "Rejects a zero cell size without dividing by it":
    check:
      newTestBuilderResult(localStore, protectedManifest, tp, NBytes 0).isErr
      newTestBuilderResult(localStore, protectedManifest, tp, NBytes 0).error.msg ==
        "Cell size must be positive."

  test "Rejects a cell size that is not a multiple of 64 bytes":
    check:
      newTestBuilderResult(localStore, protectedManifest, tp, NBytes 32).isErr
      newTestBuilderResult(localStore, protectedManifest, tp, NBytes 32).error.msg ==
        "Cell size must be a multiple of 64 bytes."

  test "Should build correct slot builder":
    builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    check:
      builder.cellSize == cellSize
      builder.numSlots == numSlots
      builder.numBlockCells == numBlockCells
      builder.numSlotBlocks == numSlotBlocksTotal
      builder.numSlotCells == (numSlotBlocksTotal + parityPerSlot) * numBlockCells
      builder.numBlocks == numBlocksTotal

  test "Uses the committed cell size for verifiable manifests":
    let
      encodedBuilder = newTestBuilder(localStore, protectedManifest, tp, NBytes 128)
      verifiableManifest = (await encodedBuilder.buildManifest(tp)).tryGet()
      rebuilt = Poseidon2Builder
        .new(
          localStore,
          localStore,
          Erasure.new(
            localStore, localStore, leoEncoderProvider, leoDecoderProvider, tp
          ),
          verifiableManifest,
        )
        .tryGet()

    check:
      rebuilt.cellSize == NBytes 128
      rebuilt.numBlockCells == (protectedManifest.blockSize div NBytes 128).int

  test "getStoredCid returns an explicitly stored padding CID":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      paddingCid = emptyCid(
          protectedManifest.cidVersion, protectedManifest.hcodec, bt.BlockCodec
        )
        .tryGet()
      paddingIndex = 1.Natural
      paddingTree = PrometheiTree.init(@[datasetBlocks[0].cid, paddingCid]).tryGet()
      paddingRoot = paddingTree.rootCid().tryGet()
      paddingProof = paddingTree.getProof(paddingIndex).tryGet()

    (await localStore.putOverlay(paddingRoot, status = Storing.some)).tryGet()

    (
      await localStore.putCidAndProof(
        paddingRoot, paddingIndex, paddingCid, paddingProof
      )
    ).tryGet()

    check (await builder.getStoredCid(paddingRoot, paddingIndex)).tryGet() == paddingCid

  test "getStoredCid rejects missing real-data metadata":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      realIndex = builder.slotIndices(0).tryGet()[0].Natural

    (await localStore.delLeafBlockMetadata(protectedManifest.treeCid, realIndex)).tryGet()
    let missing = await builder.getStoredCid(protectedManifest.treeCid, realIndex)

    check:
      missing.isErr
      missing.error of BlockNotFoundError

  test "getStoredCid rejects missing parity metadata":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      parityRoot = (await localStore.createTmpOverlay()).tryGet()
      parityIndex = protectedManifest.protectedBlocksCount.Natural
      empty = emptyCid(
          protectedManifest.cidVersion, protectedManifest.hcodec, bt.BlockCodec
        )
        .tryGet()

    discard (await builder.encodeSlot(0, parityRoot, tp)).tryGet()

    # A real parity record, not a synthesized padding identity.
    check (await builder.getStoredCid(parityRoot, parityIndex)).tryGet() != empty

    (await localStore.delLeafBlockMetadata(parityRoot, parityIndex)).tryGet()
    let missing = await builder.getStoredCid(parityRoot, parityIndex)

    check:
      missing.isErr
      missing.error of BlockNotFoundError

  test "only slot geometry synthesizes data padding":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      dataRoot = protectedManifest.treeCid
      slotIndices = builder.slotIndices(0).tryGet()
      padPosition = protectedManifest.dataBlocksPerSlot.Natural
      paddingCid = emptyCid(
          protectedManifest.cidVersion, protectedManifest.hcodec, bt.BlockCodec
        )
        .tryGet()

    check padPosition < builder.numSlotBlocks

    let
      missingPadRecord =
        await builder.getStoredCid(dataRoot, slotIndices[padPosition].Natural)
      (padData, padTree) =
        (await builder.getSlotLeafBlock(0, dataRoot, dataRoot, padPosition)).tryGet()

    check:
      missingPadRecord.isErr
      missingPadRecord.error of BlockNotFoundError
      padData == newSeqWith(blockSize.int, 0xFF'u8)
      padTree.root().tryGet() == emptyDigest

    discard (await builder.encodeSlot(0, dataRoot, tp)).tryGet()
    let
      slotRoot = (await builder.sealSlot(0, dataRoot, dataRoot, tp)).tryGet()
      slotCid = slotRoot.toSlotCid().tryGet()
      padLeaf = (await localStore.getLeafMetadata(slotCid, padPosition)).tryGet()

    check padLeaf.blkCid == paddingCid

    let realIndex = slotIndices[0].Natural
    (await localStore.delLeafBlockMetadata(dataRoot, realIndex)).tryGet()
    let missingReal = await builder.getSlotLeafBlock(0, dataRoot, dataRoot, 0.Natural)

    check:
      missingReal.isErr
      missingReal.error of BlockNotFoundError

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
          for entry in inIndexOrder(parityCids):
            let blk = (
              await localStore.getBlock(protectedManifest.treeCid, entry.index)
            ).tryGet()
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

  test "Should publish a complete verifiable tree and independently rebuilt roots":
    let
      linearStrategy = Strategy.init(
        0, protectedManifest.blocksCount - 1, numSlots, numSlots, numPadSlotBlocks
      )
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    check:
      builder.slotRoots.len == 0
      builder.verifyTree.isNone
      builder.verifyRoot.isNone
      builder.verifiableRoot.isNone

    (await builder.buildSlots(tp)).tryGet()
    let
      verifiableRoot = !builder.verifiableRoot
      expectedLeafCount =
        protectedManifest.protectedBlocksCount + numSlots * parityPerSlot
      indices = (0 ..< expectedLeafCount).toSeq.mapIt(it.Natural)
      allLeaves = (await localStore.getCidsAndProofs(verifiableRoot, indices)).tryGet()

    check:
      allLeaves.len == expectedLeafCount
      builder.slotRoots.len == numSlots
      builder.verifyTree.isSome
      builder.verifyRoot.isSome
      builder.verifiableRoot.isSome

    for index in 0 ..< expectedLeafCount:
      let (cid, proof) =
        (await localStore.getCidAndProof(verifiableRoot, index.Natural)).tryGet()
      check:
        proof.isSome
        proof.unsafeGet().verify(cid, verifiableRoot).tryGet()

      if index < protectedManifest.protectedBlocksCount:
        let protectedCid =
          (await localStore.getCid(protectedManifest.treeCid, index.Natural)).tryGet()
        check cid == protectedCid

    let
      expectedSlotRoots = collect(newSeq):
        for slotIndex in 0 ..< numSlots:
          let
            dataHashes = collect(newSeq):
              for slotPosition, blockIndex in linearStrategy.getIndices(slotIndex):
                if slotPosition >= protectedManifest.dataBlocksPerSlot:
                  emptyDigest
                else:
                  let blk = (
                    await localStore.getBlock(verifiableRoot, blockIndex.Natural)
                  ).tryGet()
                  SpongeMerkle.digest(blk.data, cellSize.int)

            parityHashes = collect(newSeq):
              for parityPosition in 0 ..< parityPerSlot:
                let blk = (
                  await localStore.getBlock(
                    verifiableRoot,
                    (
                      protectedManifest.protectedBlocksCount + slotIndex * parityPerSlot +
                      parityPosition
                    ).Natural,
                  )
                ).tryGet()
                SpongeMerkle.digest(blk.data, cellSize.int)

          Merkle.digest(dataHashes & parityHashes)

      expectedVerifyRoot = Merkle.digest(expectedSlotRoots)
      builtManifest = (await builder.buildManifest(tp)).tryGet()
      committedHash = builtManifest.verifyRoot.mhash.tryGet()
      committedVerifyRoot =
        !Poseidon2Hash.fromBytes(committedHash.digestBytes.toArray32)

    check:
      builder.slotRoots == expectedSlotRoots
      !builder.verifyRoot == expectedVerifyRoot
      builtManifest.treeCid == verifiableRoot
      builtManifest.slotRoots.len == expectedSlotRoots.len
      committedVerifyRoot == expectedVerifyRoot

    for slotIndex, slotRoot in expectedSlotRoots:
      check builtManifest.slotRoots[slotIndex] == slotRoot.toSlotCid().tryGet()

  test "Failed build cleans its private overlay and publishes no builder state":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      failureSlot = numSlots - 1
      missingIndex = builder.slotIndices(failureSlot).tryGet()[0].Natural

    (await localStore.delLeafBlockMetadata(protectedManifest.treeCid, missingIndex)).tryGet()

    let
      parityWriteStarted = newAsyncEvent()
      allowParityWrites = newAsyncEvent()

    localStore.onBlockStored = (
      proc(_: Cid): Future[void] {.async: (raises: []).} =
        parityWriteStarted.fire()
        await noCancel(allowParityWrites.wait())
    ).some
    defer:
      allowParityWrites.fire()
      localStore.onBlockStored = CidCallback.none

    let
      beforeIter = (await localStore.listOverlays()).tryGet()
      overlaysBefore = await collectAsync(beforeIter)

    let buildFut = builder.buildSlots(tp)
    await parityWriteStarted.wait()

    allowParityWrites.fire()
    let buildResult = await buildFut

    check:
      buildResult.isErr
      buildResult.error of BlockNotFoundError
      builder.slotRoots.len == 0
      builder.verifyTree.isNone
      builder.verifyRoot.isNone
      builder.verifiableRoot.isNone

    # Overlays the failed build left behind: the private temporary one must be
    # gone, and any surviving new overlay must be a completed public root.
    for status in [Storing, Finalizing, Deleting]:
      let
        strandedIter = (await localStore.listOverlaysInState(status)).tryGet()
        stranded = (await collectAsync(strandedIter)).filterIt(it notin overlaysBefore)
      check stranded.len == 0

  test "Cancelled build drains active children before private cleanup":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      probeRoot = (await localStore.createTmpOverlay()).tryGet()

    var callbackBudget = 0
    for slotIndex in 0 ..< numSlots:
      let parityCids =
        (await builder.encodeSlot(slotIndex.Natural, probeRoot, tp)).tryGet()
      callbackBudget = max(callbackBudget, parityCids.mapIt(it.cid).deduplicate.len)
    (await localStore.dropOverlay(probeRoot)).tryGet()

    let
      beforeIter = (await localStore.listOverlays()).tryGet()
      overlaysBefore = await collectAsync(beforeIter)
      childStillWriting = newAsyncEvent()
      allowChildToFinish = newAsyncEvent()

    var
      callbacksStarted = 0
      callbacksFinished = 0
      activeCallbacks = 0

    # Allow one complete parity write before gating a later child.
    localStore.onBlockStored = (
      proc(_: Cid): Future[void] {.async: (raises: []).} =
        inc callbacksStarted
        if callbacksStarted > callbackBudget:
          inc activeCallbacks
          childStillWriting.fire()
          try:
            await noCancel(allowChildToFinish.wait())
          finally:
            dec activeCallbacks
        inc callbacksFinished
    ).some
    defer:
      allowChildToFinish.fire()
      localStore.onBlockStored = CidCallback.none

    let buildFut = builder.buildSlots(tp)
    await childStillWriting.wait()

    let
      duringIter = (await localStore.listOverlays()).tryGet()
      overlaysDuring = await collectAsync(duringIter)
      newOverlays = overlaysDuring.filterIt(it notin overlaysBefore)
      cancelFut = buildFut.cancelAndWait()

    await idleAsync()
    check not cancelFut.finished

    allowChildToFinish.fire()
    await cancelFut

    check:
      callbacksStarted > callbackBudget
      callbacksFinished == callbacksStarted
      activeCallbacks == 0
      buildFut.finished
      buildFut.cancelled
      newOverlays.len == 1
      builder.slotRoots.len == 0
      builder.verifyTree.isNone
      builder.verifyRoot.isNone
      builder.verifiableRoot.isNone

    if newOverlays.len == 1:
      let
        tmpCid = newOverlays[0]
        tmpOverlay = await localStore.getOverlay(tmpCid)

      check:
        tmpOverlay.isErr
        tmpOverlay.error of KVStoreKeyNotFound
        localStore.deletingLock.count(tmpCid) == 0

    let
      finalizingIter = (await localStore.listOverlaysInState(Finalizing)).tryGet()
      finalizing = await collectAsync(finalizingIter)
    check finalizing.len == 0

  test "short final encode group preserves parity":
    let
      defaultBuilder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      defaultCids =
        (await defaultBuilder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
      builder = newTestBuilderWithControls(
        localStore,
        protectedManifest,
        tp,
        cellSize,
        SlotBuildControls(
          encodeGroupCap: 3,
          payloadIOTarget: blockSize.int div 2,
          proofMetadataTarget: 128,
        ),
      )
      targetRoot = (await localStore.createTmpOverlay()).tryGet()

    let cids = (await builder.encodeSlot(0, targetRoot, tp)).tryGet()
    (await localStore.dropOverlay(targetRoot)).tryGet()

    check inIndexOrder(cids) == inIndexOrder(defaultCids)

  test "source shorter than encode cap preserves parity":
    let
      defaultBuilder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      defaultCids =
        (await defaultBuilder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
      inputRowCount = protectedManifest.numSlotBlocksTotal
      encodeCap = inputRowCount + 1
      builder = newTestBuilderWithControls(
        localStore,
        protectedManifest,
        tp,
        cellSize,
        SlotBuildControls(
          encodeGroupCap: encodeCap,
          payloadIOTarget: blockSize.int,
          proofMetadataTarget: 128,
        ),
      )
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
      cids = (await builder.encodeSlot(0, targetRoot, tp)).tryGet()
    (await localStore.dropOverlay(targetRoot)).tryGet()

    check:
      inputRowCount < encodeCap
      inIndexOrder(cids) == inIndexOrder(defaultCids)

  test "cap one serializes fetches behind an active encode":
    firstEncodeCount.store(0)
    firstEncodeStarted.store(false)
    firstEncodeFinished.store(false)
    gatedEncodeOrdinal.store(0)
    gatedEncodeStarted.store(false)
    releaseGatedEncode.store(false)
    defer:
      releaseGatedEncode.store(true)
      gatedEncodeOrdinal.store(-1)

    let
      readStarts = newAsyncQueue[int](1024)
      store = ReadStartStore(inner: localStore, readStarts: readStarts)
      builder = Poseidon2Builder
        .new(
          store,
          localStore,
          Erasure.new(store, localStore, slowEncoderProvider, leoDecoderProvider, tp),
          protectedManifest,
          cellSize = cellSize,
          controls = SlotBuildControls(
            encodeGroupCap: 1,
            payloadIOTarget: blockSize.int * 1024,
            proofMetadataTarget: 128,
          ),
        )
        .tryGet()
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
      build = builder.encodeSlot(0, targetRoot, tp)

    var gateObserved = false
    for _ in 0 ..< 5000:
      if gatedEncodeStarted.load():
        gateObserved = true
        break
      if build.finished:
        break
      await sleepAsync(1.milliseconds)

    if gateObserved:
      check store.readIndex == 1
    releaseGatedEncode.store(true)

    let
      result = await build
      secondReadBeforeEncodeFinished = store.secondReadBeforeEncodeFinished
    (await localStore.dropOverlay(targetRoot)).tryGet()

    check:
      gateObserved
      not secondReadBeforeEncodeFinished
      firstEncodeFinished.load()
      result.isOk

  test "cap three writes later columns before the first column encode":
    firstEncodeCount.store(0)
    firstEncodeStarted.store(false)
    firstEncodeFinished.store(false)
    activeEncodes.store(0)
    peakEncodes.store(0)
    # A later full parity block must remain writable while column zero is gated.
    let
      fixtureEcK = 3
      fixtureEcM = 2
      fixtureNumDatasetBlocks = 16
      fixtureNumTotalBlocks =
        calcEcBlocksCount(fixtureNumDatasetBlocks, fixtureEcK, fixtureEcM)
      fixtureOriginalDatasetSize = fixtureNumDatasetBlocks * blockSize.int
      fixtureTotalDatasetSize = fixtureNumTotalBlocks * blockSize.int
      fixtureBlocks = deterministicDataset(blockSize.int, fixtureNumTotalBlocks)
      fixtureCreated = await createProtectedManifest(
        fixtureBlocks, localStore, fixtureNumDatasetBlocks, fixtureEcK, fixtureEcM,
        blockSize, fixtureOriginalDatasetSize, fixtureTotalDatasetSize,
      )
      localManifest = fixtureCreated.protected

    gatedEncodeOrdinal.store(localManifest.numSlotBlocksTotal)
    gatedEncodeStarted.store(false)
    releaseGatedEncode.store(false)
    defer:
      releaseGatedEncode.store(true)
      gatedEncodeOrdinal.store(-1)

    let
      defaultBuilder = newTestBuilder(localStore, localManifest, tp, cellSize)
      defaultCids =
        (await defaultBuilder.encodeSlot(0, localManifest.treeCid, tp)).tryGet()
      recording = RecordingStore(inner: localStore)
      subjectBuilder = Poseidon2Builder
        .new(
          recording,
          localStore,
          Erasure.new(
            recording, localStore, slowEncoderProvider, leoDecoderProvider, tp
          ),
          localManifest,
          cellSize = cellSize,
          controls = SlotBuildControls(
            encodeGroupCap: 3, payloadIOTarget: blockSize.int, proofMetadataTarget: 128
          ),
        )
        .tryGet()
      firstPassParityBlocks = localManifest.firstPassParityBlocks(
        subjectBuilder.numBlockCells, subjectBuilder.numSlotBlocks
      )
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
      build = subjectBuilder.encodeSlot(0, targetRoot, tp)

    var gateObserved = false
    for _ in 0 ..< 5000:
      if gatedEncodeStarted.load():
        gateObserved = true
        break
      if build.finished:
        break
      await sleepAsync(1.milliseconds)

    var columnWriteObserved = false
    if gateObserved:
      for _ in 0 ..< 5000:
        if recording.writeBatchSizes.len > firstPassParityBlocks:
          columnWriteObserved = true
          break
        if build.finished:
          break
        await sleepAsync(1.milliseconds)

    releaseGatedEncode.store(true)
    let cids = (await build).tryGet()
    (await localStore.dropOverlay(targetRoot)).tryGet()

    check:
      gateObserved
      columnWriteObserved
      inIndexOrder(cids) == inIndexOrder(defaultCids)
      recording.peakReads <= 3
      peakEncodes.load() <= 3
      peakEncodes.load() >= 2

  test "read failure settles active encodes":
    firstEncodeCount.store(0)
    firstEncodeStarted.store(false)
    firstEncodeFinished.store(false)
    activeEncodes.store(0)
    gatedEncodeOrdinal.store(0)
    gatedEncodeStarted.store(false)
    releaseGatedEncode.store(false)
    defer:
      releaseGatedEncode.store(true)
      gatedEncodeOrdinal.store(-1)

    let
      store = FailReadStore(inner: localStore)
      builder = Poseidon2Builder
        .new(
          store,
          localStore,
          Erasure.new(
            localStore, localStore, slowEncoderProvider, leoDecoderProvider, tp
          ),
          protectedManifest,
          cellSize = cellSize,
          controls = SlotBuildControls(
            encodeGroupCap: 3,
            payloadIOTarget: blockSize.int * 1024,
            proofMetadataTarget: 128,
          ),
        )
        .tryGet()
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
      build = builder.encodeSlot(0, targetRoot, tp)

    var readFailureObserved = false
    for _ in 0 ..< 5000:
      if store.readFailureEmitted:
        readFailureObserved = true
        break
      if build.finished:
        break
      await sleepAsync(1.milliseconds)

    await idleAsync()
    let pendingWhileGated = not build.finished
    releaseGatedEncode.store(true)

    let result = await build
    (await localStore.dropOverlay(targetRoot)).tryGet()

    check:
      readFailureObserved
      gatedEncodeStarted.load()
      pendingWhileGated
      result.isErr
      result.error of BlockNotFoundError
      activeEncodes.load() == 0

  test "cancelled stripe read does not hang the build":
    let
      networkStore = CancelFirstReadStore(inner: localStore)
      builder = Poseidon2Builder
        .new(
          networkStore,
          localStore,
          Erasure.new(
            networkStore, localStore, leoEncoderProvider, leoDecoderProvider, tp
          ),
          protectedManifest,
          cellSize = cellSize,
          controls = SlotBuildControls(
            encodeGroupCap: 3,
            payloadIOTarget: blockSize.int div 2,
            proofMetadataTarget: 128,
          ),
        )
        .tryGet()
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
      build = builder.encodeSlot(0, targetRoot, tp)

    var finished = false
    try:
      finished = await withTimeout(build, 5.seconds)
    except CancelledError:
      finished = build.finished

    if not build.finished:
      await noCancel build.cancelAndWait()

    (await localStore.dropOverlay(targetRoot)).tryGet()

    check:
      finished
      build.finished
      build.cancelled or (build.failed and build.error of CancelledError)

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
    numSlotBlocksTotal = max(nextPowerOfTwo(numSlotBlocks), InnerCodeK.int)
    numPadSlotBlocks = numSlotBlocksTotal - numSlotBlocks

    nRow = numBlockCells * InnerCodeN.int div InnerCodeK.int
    nCol = numSlotBlocksTotal * InnerCodeN.int div InnerCodeK.int
    parityPerSlot =
      divUp(numSlotBlocksTotal * (nRow - numBlockCells), numBlockCells) +
      divUp(nRow * (nCol - numSlotBlocksTotal), numBlockCells)

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
    let cellRefCount =
      if err =? cellRefCountRes.errorOption:
        0
      else:
        cellRefCountRes.tryGet()

    # No metadata entry for the cell CID is acceptable; anything else must be 0.
    check cellRefCount == 0

  test "Multiple slots referencing same block increment refcount correctly":
    let builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)

    # Build all slots
    (await builder.buildSlots(tp)).tryGet()

    # Get refcount on first dataset block
    let firstBlockCid = datasetBlocks[0].cid
    let refCount = (await localStore.blockRefCount(firstBlockCid)).tryGet()

    # Refcount should be 1 (block is referenced by one slot in EC distribution)
    check refCount >= 1

suite "Streaming slot encoding compatibility":
  ## Streaming must not change parity bytes, block boundaries, CIDs, or
  ## commitments for the existing encoding geometry.
  let
    blockSize = NBytes 1024
    cellSize = NBytes 64
    ecK = 3
    ecM = 2
    numSlots = ecK + ecM
    numDatasetBlocks = 8
    numTotalBlocks = calcEcBlocksCount(numDatasetBlocks, ecK, ecM)
    originalDatasetSize = numDatasetBlocks * blockSize.int
    totalDatasetSize = numTotalBlocks * blockSize.int
    expectedSlot0Cids =
      @[
        "zDxWB8EDAMnD4QR7WbDSJongckUSgVH5g5NgStHRCYC9W7AhaFNJ",
        "zDxWB8ECzgshTQLmMEouKpoq12jxQiGJBRspeGkAm8FBHB4N8qp4",
        "zDxWB8ED8KHUHbyzgMu3ceNXYX5Ugv7f9v8RtPPHmU2ws42Vsqx2",
        "zDxWB8ED4y3J3mhW5UcLUYZgDRpq44skNu6ucmiY7QFKKPyRXmJ9",
        "zDxWB8ECzpyGDXE6E1ds3BmbbcA6HCQZRwMgkm6iHXRLbviKTqJ7",
        "zDxWB8ED6joZ1SLBBYvBoKtauxxPJpk1Rqia6TEuidRht4YBhWER",
        "zDxWB8ED4LHJD8asfDG8CEN4pcGQDyPB9t3unsCRNmvJadK8oB6J",
        "zDxWB8ECzooZQGnbSp3uX8tFvzMfcabYJ7MAkjsNngQ1jx57DC99",
        "zDxWB8EDEpicKc3Hmm2wnJR3kCuJUUAS7nHGnGqBct6LrsCfPAkP",
        "zDxWB8ED5uogRivpd4Fg2mtwhWnuuFow9FgnFLCXHobF3fme4N8j",
        "zDxWB8EDE7eV8jJQbH6EJDSTZdMdYuLkJkMYpWQadctFh6tyrHQm",
        "zDxWB8ECyG7HCi7BLRpHLiCsYhNurckqZkRLoSgWU1uFRxxViMcC",
      ]
    expectedSlot0Root = "zE2PfUHWNuL8T8MDG8RfKc51nKNoSuL8QuZijw74ZG4fuT1ymGA3"
    expectedSlotLastCids =
      @[
        "zDxWB8ED123XGyHAQer6jKu7u2gQDbwR6gNnzm2qGoSZZrLXyzVX",
        "zDxWB8ED9aFNvm5efFhUSs7PHDmAFcnYTBZL33bN3rCZJ52ZPXxj",
        "zDxWB8ED5AhxYA1nAM1fNqAJ3Tcj54eS3bj3kF4HHUKwzB6Nsosi",
        "zDxWB8ED4y3J3mhW5UcLUYZgDRpq44skNu6ucmiY7QFKKPyRXmJ9",
        "zDxWB8ED26imb6SmrMbNzSvckbvy6HkaC7aDxBoZ52f8Ho4iio51",
        "zDxWB8EDDqGpS2cxK25QngRoMqBGVXhA3nj99kKJeoFEkNtwn86Q",
        "zDxWB8ED2Zmj2CTPHjyzTPYD4wucNnnPS8AXSKzY8y3iuFBYWNSZ",
        "zDxWB8EDF4o2zQEZMDgLatLZURVm8hZZpT1HLivyqHDnynUbifxS",
        "zDxWB8EDCN74fSJ1MEromeKKPq7per2GAzdfgQFpKZJkMvYpLSD2",
        "zDxWB8ED1Q5RFQFQK7xKet48EKhqHa1xotwWHoBHn2e37BTwHX7R",
        "zDxWB8EDAk8xVHsrqd5BbJ3H1rNCx4RDLiqTfDt8ayqd7HF2VSA1",
        "zDxWB8ECxsrFaoXkEUbsCm17z5JYf4Q83yCM7KtFvwkgQ6tCZ1aA",
      ]
    expectedSlotLastRoot = "zE2PfUHWEyyMFtHpLKiDmNTA9YHxmCYjzXqseNjBV7uhhkDvtYKY"
    expectedVerifyRoot = "zDzSvJTfB6Mth8yXyqkxJ246orSX6pYaXokHQmgBiv5yHMrzSW5D"

  var
    datasetBlocks: seq[bt.Block]
    localStore: RepoStore
    protectedManifest: Manifest
    tp: Taskpool

  setup:
    tp = Taskpool.new(num_threads = 4)
    let
      repoDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()
      metaDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()
    localStore = RepoStore.new(repoDs, metaDs)
    datasetBlocks = deterministicDataset(blockSize.int, numTotalBlocks)

    let created = await createProtectedManifest(
      datasetBlocks, localStore, numDatasetBlocks, ecK, ecM, blockSize,
      originalDatasetSize, totalDatasetSize,
    )

    protectedManifest = created[1]

  teardown:
    await localStore.close()
    tp.shutdown()
    reset(datasetBlocks)
    reset(localStore)
    reset(protectedManifest)

  test "default controls reproduce pre-streaming parity and roots":
    let
      builder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      last = numSlots - 1
      slot0 = (await builder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
      root0 = (
        await builder.sealSlot(
          0, protectedManifest.treeCid, protectedManifest.treeCid, tp
        )
      ).tryGet()
      slotLast =
        (await builder.encodeSlot(last.Natural, protectedManifest.treeCid, tp)).tryGet()
      rootLast = (
        await builder.sealSlot(
          last.Natural, protectedManifest.treeCid, protectedManifest.treeCid, tp
        )
      ).tryGet()

    when InnerCodeK == 1 and InnerCodeN == 2:
      check:
        inIndexOrder(slot0).mapIt($it.cid) == expectedSlot0Cids
        $root0.toSlotCid().tryGet() == expectedSlot0Root
        inIndexOrder(slotLast).mapIt($it.cid) == expectedSlotLastCids
        $rootLast.toSlotCid().tryGet() == expectedSlotLastRoot
    else:
      check slot0.len == slotLast.len

  test "stripe jobs are lazy and complete across column regions":
    let
      recording = RecordingStore(inner: localStore)
      builder = Poseidon2Builder.new(
        recording,
        localStore,
        Erasure.new(localStore, localStore, leoEncoderProvider, leoDecoderProvider, tp),
        protectedManifest,
        cellSize = cellSize,
      ).tryGet
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
    discard (await builder.encodeSlot(0, targetRoot, tp)).tryGet()
    recording.readBatchSizes.setLen(0)

    let
      cellsPerBlock = (blockSize div cellSize).int
      inputRowCount = protectedManifest.numSlotBlocksTotal
      rowShards = cellsPerBlock * InnerCodeN.int div InnerCodeK.int
      slotStrategy = LinearStrategy.init(
        0,
        protectedManifest.protectedBlocksCount - 1,
        numSlots,
        numSlots,
        protectedManifest.numPadSlotBlocks,
      )

    let rowIterator = rowStripes(
        recording, protectedManifest, slotStrategy, 0, cellSize, blockSize.int
      )
      .tryGet()
    defer:
      rowIterator.dispose()
    check recording.readBatchSizes.len == 0

    let rowStripe = (await rowIterator.next()).tryGet()
    check:
      rowStripe.len == cellsPerBlock
      recording.readBatchSizes.len > 0

    recording.readBatchSizes.setLen(0)
    let columnIterator = columnStripes(
        recording, localStore, protectedManifest, slotStrategy, 0, targetRoot, cellSize,
        blockSize.int,
      )
      .tryGet()
    defer:
      columnIterator.dispose()
    check recording.readBatchSizes.len == 0

    for columnIndex in 0 ..< rowShards:
      let columnStripe = (await columnIterator.next()).tryGet()
      check columnStripe.len == inputRowCount

    check recording.readBatchSizes.len > 0
    (await localStore.dropOverlay(targetRoot)).tryGet()

  test "bounded control values preserve parity and commitments":
    let
      controls = SlotBuildControls(
        encodeGroupCap: 1,
        payloadIOTarget: blockSize.int div 2,
        proofMetadataTarget: 128,
      )
      defaultBuilder = newTestBuilder(localStore, protectedManifest, tp, cellSize)
      defaultCids =
        (await defaultBuilder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
      defaultRoot = (
        await defaultBuilder.sealSlot(
          0, protectedManifest.treeCid, protectedManifest.treeCid, tp
        )
      ).tryGet()
      builder = newTestBuilderWithControls(
        localStore, protectedManifest, tp, cellSize, controls
      )
      cids = (await builder.encodeSlot(0, protectedManifest.treeCid, tp)).tryGet()
      root = (
        await builder.sealSlot(
          0, protectedManifest.treeCid, protectedManifest.treeCid, tp
        )
      ).tryGet()

    check:
      inIndexOrder(cids) == inIndexOrder(defaultCids)
      root.toSlotCid().tryGet() == defaultRoot.toSlotCid().tryGet()

    when InnerCodeK == 1 and InnerCodeN == 2:
      check:
        inIndexOrder(cids).mapIt($it.cid) == expectedSlot0Cids
        $root.toSlotCid().tryGet() == expectedSlot0Root

    let
      defaultRepoDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()
      defaultMetaDs = SQLiteKVStore.new(SqliteMemory, tp).tryGet()
      defaultStore = RepoStore.new(defaultRepoDs, defaultMetaDs)
      defaultBlocks = deterministicDataset(blockSize.int, numTotalBlocks)
      defaultCreated = await createProtectedManifest(
        defaultBlocks, defaultStore, numDatasetBlocks, ecK, ecM, blockSize,
        originalDatasetSize, totalDatasetSize,
      )
      defaultManifest = defaultCreated[1]
      defaultBuild = newTestBuilder(defaultStore, defaultManifest, tp, cellSize)

    (await builder.buildSlots(tp)).tryGet()
    (await defaultBuild.buildSlots(tp)).tryGet()

    check:
      builder.verifiableRoot.isSome
      builder.verifyRoot.isSome
      defaultBuild.verifiableRoot == builder.verifiableRoot
      defaultBuild.verifyRoot == builder.verifyRoot
      defaultBuild.slotRoots == builder.slotRoots

    when InnerCodeK == 1 and InnerCodeN == 2:
      check $(!builder.verifiableRoot) == expectedVerifyRoot

    await defaultStore.close()

  test "missing source block in a bounded batch is a typed failure":
    let
      controls = SlotBuildControls(
        encodeGroupCap: 3,
        payloadIOTarget: blockSize.int div 2,
        proofMetadataTarget: 128,
      )
      builder = newTestBuilderWithControls(
        localStore, protectedManifest, tp, cellSize, controls
      )

    # Pick an unshared outer-parity leaf that is not the first row of its
    # encode group, so earlier encodes are active when the batch fails.
    var
      targetSlot = -1
      targetIndex = 0.Natural
    for slot in 0 ..< numSlots:
      let slotIndices = builder.slotIndices(slot).tryGet()
      for pos, idx in slotIndices:
        if pos >= 2 and idx >= protectedManifest.originalBlocksCount and
            idx < protectedManifest.protectedBlocksCount:
          targetSlot = slot
          targetIndex = idx.Natural
          break
      if targetSlot >= 0:
        break

    check targetSlot >= 0

    if targetSlot >= 0:
      (await localStore.delLeafBlockMetadata(protectedManifest.treeCid, targetIndex)).tryGet()

      let
        targetRoot = (await localStore.createTmpOverlay()).tryGet()
        res = await builder.encodeSlot(targetSlot.Natural, targetRoot, tp)
      (await localStore.dropOverlay(targetRoot)).tryGet()

      check:
        res.isErr
        res.error of BlockNotFoundError

  test "streamed parity persists indexed blocks without changing source metadata":
    let
      sourceBlocksCount = 4
      protectedBlocksCount = calcEcBlocksCount(sourceBlocksCount, ecK, ecM)
      sourceSize = sourceBlocksCount * blockSize.int
      protectedSize = protectedBlocksCount * blockSize.int
      persistenceBlocks = deterministicDataset(blockSize.int, protectedBlocksCount)
      created = await createProtectedManifest(
        persistenceBlocks, localStore, sourceBlocksCount, ecK, ecM, blockSize,
        sourceSize, protectedSize,
      )
      persistenceManifest = created[1]
      sourceRoot = persistenceManifest.treeCid
      slotIndex = 1.Natural
      cellsPerBlock = (blockSize div cellSize).int
      slotBlocks = persistenceManifest.numSlotBlocksTotal
      rowShards = persistenceManifest.rowShards(cellsPerBlock)
      columnShards = persistenceManifest.colShards(cellsPerBlock, slotBlocks)
      rowLogicalCells = slotBlocks * (rowShards - cellsPerBlock)
      columnLogicalCells = rowShards * (columnShards - slotBlocks)
      firstPassBlocks = divUp(rowLogicalCells, cellsPerBlock)
      secondPassBlocks = divUp(columnLogicalCells, cellsPerBlock)
      parityBlocksPerSlot =
        persistenceManifest.parityBlocksPerSlot(cellsPerBlock, slotBlocks)
      parityStart = (
        persistenceManifest.protectedBlocksCount + slotIndex.int * parityBlocksPerSlot
      ).Natural
      passGeometry = [
        (startIndex: parityStart, logicalCells: rowLogicalCells),
        (
          startIndex: parityStart + firstPassBlocks.Natural,
          logicalCells: columnLogicalCells,
        ),
      ]

    check:
      firstPassBlocks + secondPassBlocks == parityBlocksPerSlot
      rowLogicalCells mod cellsPerBlock == 0

    let columnRemainder = columnLogicalCells mod cellsPerBlock
    when InnerCodeK == 1 and InnerCodeN == 2:
      check columnRemainder == 0
    elif InnerCodeK == 2 and InnerCodeN == 3:
      check columnRemainder == 8
    elif InnerCodeK == 4 and InnerCodeN == 5:
      check columnRemainder == 4

    var
      sourceCids: seq[Cid]
      indexedOutputs: seq[seq[tuple[index: Natural, cid: Cid]]]
    for index in 0 ..< persistenceManifest.protectedBlocksCount:
      sourceCids.add((await localStore.getCid(sourceRoot, index.Natural)).tryGet())

    for encodeCap in [1, 3]:
      let
        controls = SlotBuildControls(
          encodeGroupCap: encodeCap,
          payloadIOTarget: blockSize.int * 1024,
          proofMetadataTarget: 128,
        )
        builder = newTestBuilderWithControls(
          localStore, persistenceManifest, tp, cellSize, controls
        )
        targetRoot = (await localStore.createTmpOverlay()).tryGet()
        entries = (await builder.encodeSlot(slotIndex, targetRoot, tp)).tryGet()
        ordered = inIndexOrder(entries)

      check ordered.len == parityBlocksPerSlot

      for offset, entry in ordered:
        check entry.index == parityStart + offset
        let storedBlock = (await localStore.getBlock(targetRoot, entry.index)).tryGet()
        check storedBlock.cid == entry.cid

      for pass in passGeometry:
        let remainder = pass.logicalCells mod cellsPerBlock
        if remainder > 0:
          let
            finalIndex = pass.startIndex + (pass.logicalCells div cellsPerBlock).Natural
            finalBlock = (await localStore.getBlock(targetRoot, finalIndex)).tryGet()
            tailStart = remainder * cellSize.int

          check finalBlock.data.len == blockSize.int
          for byteIndex in tailStart ..< finalBlock.data.len:
            check finalBlock.data[byteIndex] == 0'u8

      indexedOutputs.add ordered
      (await localStore.dropOverlay(targetRoot)).tryGet()

    check indexedOutputs[0] == indexedOutputs[1]

    for index, sourceCid in sourceCids:
      let storedCid = (await localStore.getCid(sourceRoot, index.Natural)).tryGet()
      check storedCid == sourceCid

  test "parity write failures propagate from batch and trailing flushes":
    for payloadTarget in [blockSize.int, blockSize.int * 1024]:
      let
        recording = RecordingStore(inner: localStore)
        builder = Poseidon2Builder
          .new(
            recording,
            localStore,
            Erasure.new(
              localStore, localStore, leoEncoderProvider, leoDecoderProvider, tp
            ),
            protectedManifest,
            cellSize = cellSize,
            controls = SlotBuildControls(
              encodeGroupCap: 1,
              payloadIOTarget: payloadTarget,
              proofMetadataTarget: 128,
            ),
          )
          .tryGet()
        targetRoot = (await localStore.createTmpOverlay()).tryGet()
      (await localStore.putOverlay(targetRoot, status = Deleting.some)).tryGet()

      let
        encoded = await builder.encodeSlot(0, targetRoot, tp)
        missing = await builder.getStoredCid(
          targetRoot, protectedManifest.protectedBlocksCount.Natural
        )
      (await localStore.dropOverlay(targetRoot)).tryGet()

      check:
        encoded.isErr
        encoded.error of OverlayDeletingError
        recording.writeBatchSizes.len == 1
        missing.isErr
        missing.error of BlockNotFoundError

  test "rejects non-positive controls":
    let res = Poseidon2Builder.new(
      localStore,
      localStore,
      Erasure.new(localStore, localStore, leoEncoderProvider, leoDecoderProvider, tp),
      protectedManifest,
      cellSize = cellSize,
      controls =
        SlotBuildControls(encodeGroupCap: 0, payloadIOTarget: 1, proofMetadataTarget: 1),
    )

    check res.isErr

  test "column results larger than the write target are chunked":
    # This one-cell geometry is specific to the default 1:2 rate.
    if InnerCodeK != 1 or InnerCodeN != 2:
      return

    # One cell per block and four blocks per slot makes each column result
    # span four blocks, while the write target admits only one.
    let
      packBlockSize = NBytes 64
      packCellSize = NBytes 64
      packEcK = 2
      packEcM = 1
      packNumDatasetBlocks = 8
      packNumTotalBlocks = calcEcBlocksCount(packNumDatasetBlocks, packEcK, packEcM)
      packOriginalSize = packNumDatasetBlocks * packBlockSize.int
      packTotalSize = packNumTotalBlocks * packBlockSize.int
      packBlocks = deterministicDataset(packBlockSize.int, packNumTotalBlocks)
      packCreated = await createProtectedManifest(
        packBlocks, localStore, packNumDatasetBlocks, packEcK, packEcM, packBlockSize,
        packOriginalSize, packTotalSize,
      )
      packManifest = packCreated[1]
      controls = SlotBuildControls(
        encodeGroupCap: 1,
        payloadIOTarget: packBlockSize.int,
        proofMetadataTarget: packBlockSize.int,
      )
      recording = RecordingStore(inner: localStore)
      builder = Poseidon2Builder.new(
        recording,
        localStore,
        Erasure.new(localStore, localStore, leoEncoderProvider, leoDecoderProvider, tp),
        packManifest,
        cellSize = packCellSize,
        controls = controls,
      ).tryGet
      targetRoot = (await localStore.createTmpOverlay()).tryGet()
      cids = (await builder.encodeSlot(0, targetRoot, tp)).tryGet()
    (await localStore.dropOverlay(targetRoot)).tryGet()

    check:
      cids.len == packManifest.parityBlocksPerSlot(1, 4)
      recording.writeBatchSizes.len > 0
      recording.writeBatchSizes.allIt(it == 1)
