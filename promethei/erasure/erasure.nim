{.push raises: [].}

import std/[sugar, atomics, sequtils]

import pkg/iter
import pkg/chronos
import pkg/chronos/threadsync
import pkg/chronicles
import pkg/libp2p/[multicodec, cid, multihash]
import pkg/libp2p/protobuf/minprotobuf
import pkg/taskpools

import ../logutils
import ../manifest
import ../merkletree
import ../merkletree/promethei/asynctree
import ../stores
import ../blocktype as bt
import ../utils
import ../indexingstrategy
import ../errors

import pkg/stew/byteutils

import ./backend

export backend

logScope:
  topics = "promethei erasure"

type
  ## Encode a manifest into one that is erasure protected.
  ##
  ## The new manifest has K `blocks` that are encoded into
  ## additional M `parity` blocks. The resulting dataset
  ## is padded with empty blocks if it doesn't have a square
  ## shape.
  ##
  ## NOTE: The padding blocks could be excluded
  ## from transmission, but they aren't for now.
  ##
  ## The resulting dataset is logically divided into rows
  ## where a row is made up of B blocks. There are then,
  ## K + M = N rows in total, each of length B blocks. Rows
  ## are assumed to be of the same number of (B) blocks.
  ##
  ## The encoding is systematic and the rows can be
  ## read sequentially by any node without decoding.
  ##
  ## Decoding is possible with any K rows or partial K
  ## columns (with up to M blocks missing per column),
  ## or any combination there of.
  ##
  EncoderProvider* = proc(size, blocks, parity: int): EncoderBackend {.
    raises: [Defect], noSideEffect, nimcall
  .}

  DecoderProvider* = proc(size, blocks, parity: int): DecoderBackend {.
    raises: [Defect], noSideEffect, nimcall
  .}

  Erasure* = ref object
    taskPool: Taskpool
    encoderProvider*: EncoderProvider
    decoderProvider*: DecoderProvider
    networkStore*: BlockStore
    repoStore*: RepoStore

  EncodingParams = object
    blockSize: NBytes
    ecK: Natural
    ecM: Natural
    rounded: Natural
    steps: Natural
    blocksCount: Natural
    encodedBlocksCount: Natural
    strategy: StrategyType
    emptyCid: Cid

  ErasureError* = object of PrometheiError
  InsufficientBlocksError* = object of ErasureError
    # Minimum size, in bytes, that the dataset must have had
    # for the encoding request to have succeeded with the parameters
    # provided.
    minSize*: NBytes

func indexToPos(steps, idx, step: int): int {.inline.} =
  ## Convert an index to a position in the encoded
  ##  dataset
  ## `idx`  - the index to convert
  ## `step` - the current step
  ## `pos`  - the position in the encoded dataset
  ##

  (idx - step) div steps

proc getPendingBlocks(
    self: Erasure, treeCid: Cid, indices: seq[int]
): AsyncIter[(?!bt.Block, int)] =
  ## Get pending blocks iterator
  ##
  var
    pendingBlocks: seq[Future[(?!bt.Block, int)]] = @[]
    disposed = false

  proc attachIndex(
      fut: Future[?!bt.Block], i: int
  ): Future[(?!bt.Block, int)] {.async.} =
    ## avoids closure capture issues
    return (await fut, i)

  for blockIndex in indices:
    # request blocks from the store
    let fut = self.networkStore.getBlock(treeCid, blockIndex)
    pendingBlocks.add(attachIndex(fut, blockIndex))

  proc isFinished(): bool =
    disposed or pendingBlocks.len == 0

  proc dispose(): Future[void] {.async.} =
    disposed = true
    pendingBlocks.setLen(0)

  proc isDisposed(): bool =
    disposed

  proc genNext(): Future[(?!bt.Block, int)] {.async.} =
    let completedFut = await one(pendingBlocks)
    if (let i = pendingBlocks.find(completedFut); i >= 0):
      pendingBlocks.del(i)
      return await completedFut
    else:
      let (_, index) = await completedFut
      raise newException(
        CatchableError,
        "Future for block id not found, tree cid: " & $treeCid & ", index: " & $index,
      )

  AsyncIter[(?!bt.Block, int)].new(genNext, isFinished, dispose, isDisposed)

proc prepareEncodingData(
    self: Erasure,
    treeCid: Cid,
    params: EncodingParams,
    step: Natural,
    data: sink seq[seq[byte]],
    cids: ref seq[Cid],
    emptyCid: Cid,
    emptyBlock: seq[byte],
): Future[?!(Natural, seq[seq[byte]])] {.async: (raises: [CancelledError]).} =
  ## Prepare data for encoding
  ##

  logScope:
    treeCid = treeCid
    step = step
    blocksCount = params.blocksCount
    rounded = params.rounded
    strategy = params.strategy

  trace "Preparing encoding data"
  let
    strategy =
      ?catch(
        params.strategy.init(
          firstIndex = 0, lastIndex = params.rounded - 1, iterations = params.steps
        )
      )
    indices = toSeq(?catch(strategy.getIndices(step)))
    pendingBlocksIter =
      self.getPendingBlocks(treeCid, indices.filterIt(it < params.blocksCount))

  defer:
    if err =? catchAsync(await pendingBlocksIter.dispose()).errorOption:
      warn "Failed to dispose pending encoding block iterator", err = err.msg

  var resolved = 0
  while not pendingBlocksIter.finished:
    let
      (blkOrErr, idx) = ?catchAsync(await pendingBlocksIter.next())
      blk = ?blkOrErr

    let pos = indexToPos(params.steps, idx, step)
    data[pos] = if blk.isEmpty: emptyBlock else: blk.data
    cids[idx] = blk.cid

    resolved.inc()

  for idx in indices.filterIt(it >= params.blocksCount):
    let pos = indexToPos(params.steps, idx, step)
    trace "Padding with empty block", idx
    data[pos] = emptyBlock
    cids[idx] = emptyCid

  success((resolved.Natural, move data))

proc prepareDecodingData(
    self: Erasure,
    treeCid: Cid,
    params: EncodingParams,
    step: Natural,
    data: sink seq[seq[byte]],
    parityData: sink seq[seq[byte]],
    cids: ref seq[Cid],
    emptyBlock: seq[byte],
): Future[?!(Natural, Natural, seq[seq[byte]], seq[seq[byte]])] {.
    async: (raises: [CancelledError])
.} =
  ## Prepare data for decoding
  ## `treeCid`    - the tree cid to fetch blocks from
  ## `params`     - encoding parameters
  ## `step`       - the current step
  ## `data`       - the data to be prepared
  ## `parityData` - the parityData to be prepared
  ## `cids`       - cids of prepared data
  ## `emptyBlock` - the empty block to be used for padding
  ##

  let
    strategy =
      ?catch(
        params.strategy.init(
          firstIndex = 0,
          lastIndex = params.encodedBlocksCount - 1,
          iterations = params.steps,
        )
      )
    indices = toSeq(?catch(strategy.getIndices(step)))
    pendingBlocksIter = self.getPendingBlocks(treeCid, indices)

  defer:
    if err =? catchAsync(await pendingBlocksIter.dispose()).errorOption:
      warn "Failed to dispose pending decoding block iterator", err = err.msg

  var
    dataPieces = 0
    parityPieces = 0
    resolved = 0
  while not pendingBlocksIter.finished and resolved < params.ecK:
    # Continue to receive blocks until we have just enough for decoding
    # or no more blocks can arrive
    let (blkOrErr, idx) = ?catchAsync(await pendingBlocksIter.next())
    without blk =? blkOrErr, err:
      trace "Failed retrieving a block", idx, treeCid = treeCid, msg = err.msg
      continue

    let pos = indexToPos(params.steps, idx, step)

    logScope:
      cid = blk.cid
      idx = idx
      pos = pos
      step = step
      empty = blk.isEmpty

    # Guard the slot indices before any write: an out-of-range position
    # must fail the decode, not corrupt the heap (no bounds checks under
    # -d:danger).
    if pos < 0 or pos >= params.ecK + params.ecM:
      error "Decoded block position out of range",
        pos, idx, step, ecK = params.ecK, ecM = params.ecM,
        rounded = params.rounded, steps = params.steps
      return failure("Decoded block position out of range")
    if idx < params.rounded and pos >= params.ecK:
      error "Data block position exceeds ecK", pos, idx, step
      return failure("Data block position exceeds ecK")
    if idx >= params.rounded and pos < params.ecK:
      error "Parity block position below ecK", pos, idx, step
      return failure("Parity block position below ecK")
    if idx < 0 or idx >= cids[].len:
      error "Block index out of range", idx, cidsLen = cids[].len
      return failure("Block index out of range")
    cids[idx] = blk.cid
    if idx >= params.rounded:
      trace "Retrieved parity block"
      parityData[pos - params.ecK] = if blk.isEmpty: emptyBlock else: blk.data
      parityPieces.inc
    else:
      trace "Retrieved data block"
      data[pos] = if blk.isEmpty: emptyBlock else: blk.data
      dataPieces.inc

    resolved.inc

  return success (dataPieces.Natural, parityPieces.Natural, move data, move parityData)

proc init*(
    _: type EncodingParams,
    manifest: Manifest,
    ecK: Natural,
    ecM: Natural,
    strategy: StrategyType,
    emptyCid: Cid,
): ?!EncodingParams =
  if ecK > manifest.blocksCount:
    let exc = (ref InsufficientBlocksError)(
      msg:
        "Unable to encode manifest, not enough blocks, ecK = " & $ecK &
        ", blocksCount = " & $manifest.blocksCount,
      minSize: ecK.NBytes * manifest.blockSize,
    )
    return failure(exc)

  let
    rounded = roundUp(manifest.blocksCount, ecK)
    steps = divUp(rounded, ecK)

  success EncodingParams(
    blockSize: manifest.blockSize,
    ecK: ecK,
    ecM: ecM,
    rounded: rounded,
    steps: steps,
    blocksCount: manifest.blocksCount,
    encodedBlocksCount: rounded + (steps * ecM),
    strategy: strategy,
    emptyCid: emptyCid,
  )

proc initFromEncoded*(
    _: type EncodingParams, encoded: Manifest, emptyCid: Cid
): EncodingParams =
  ## Construct EncodingParams from an already-encoded manifest.
  ##
  EncodingParams(
    blockSize: encoded.blockSize,
    ecK: encoded.ecK,
    ecM: encoded.ecM,
    rounded: encoded.rounded,
    steps: encoded.steps,
    blocksCount: encoded.originalBlocksCount,
    encodedBlocksCount: encoded.blocksCount,
    strategy: encoded.protectedStrategy,
  )

proc leopardEncodeTask*(
    ctx: SharedPtr[TaskCtx[seq[seq[byte]]]],
    erasure: ptr Erasure,
    blockSize: int,
    blocks: ptr seq[seq[byte]],
    parity: ptr seq[seq[byte]],
) {.gcsafe, raises: [].} =
  let encoder = erasure.encoderProvider(blockSize, blocks[].len, parity[].len)
  defer:
    encoder.release()
    if err =? ctx[].signal.fireSync().errorOption:
      warn "Failed to fire worker completion signal", error = err

  if (let res = encoder.encode(blocks[], parity[]); res.isErr):
    warn "Error from leopard encoder backend!", error = $res.error
    ctx[].result = ThreadSpawnRes[seq[seq[byte]]].err($res.error)
  else:
    ctx[].result = ThreadSpawnRes[seq[seq[byte]]].ok(move parity[])

proc encodeStripes*(
    self: Erasure,
    stripes: sink seq[seq[byte]], # k equal-length shards, one stripe
    parityCount: Natural, # n - k parity shards to produce
): Future[?!seq[seq[byte]]] {.async: (raises: [CancelledError]).} =
  ## Encode one stripe of k equal-length shards into `parityCount` parity
  ## shards. No storage, no CIDs, no source root. Callers zero-fill pad
  ## shards before calling.
  ##
  if stripes.len == 0:
    return failure "No shards to encode"

  let shardLen = stripes[0].len
  for shard in stripes:
    if shard.len != shardLen:
      return failure "Mismatched shard lengths in encodeStripes"

  var
    data = stripes
    parity = newSeqWith(parityCount, newSeq[byte](shardLen))

  # Encode on the taskpool: the structures are moved through the
  # spawnJoin result channel, no GC refs cross the boundary.
  try:
    parity =
      ?await spawnJoin(
        proc(ctx: SharedPtr[TaskCtx[seq[seq[byte]]]]) {.gcsafe, raises: [].} =
          self.taskPool.spawn leopardEncodeTask(
            ctx, addr self, shardLen, addr data, addr parity
          )
      )
  except SpawnContractError as e:
    return failure(e)

  success parity

proc encodeData(
    self: Erasure, originalTreeCid: Cid, tmpTreeCid: Cid, params: EncodingParams
): Future[?!ref seq[Cid]] {.async: (raises: [CancelledError]).} =
  ## Encode blocks and return the cids of all blocks (data + parity).
  ## Tree construction, proof storage, and manifest creation are
  ## handled by the caller.
  ##
  logScope:
    originalTreeCid = originalTreeCid
    tmpTreeCid = tmpTreeCid
    steps = params.steps
    roundedBlocks = params.rounded
    blocksCount = params.blocksCount
    encodedBlocksCount = params.encodedBlocksCount
    ecK = params.ecK
    ecM = params.ecM

  trace "Starting erasure coding dataset"
  var
    cids = seq[Cid].new()
    emptyBlock = newSeqWith(params.blockSize.int, 0xFF'u8)

  cids[].setLen(params.encodedBlocksCount)
  for step in 0 ..< params.steps:
    # TODO: Don't allocate a new seq every time, allocate once and zero out
    var
      # Fresh payload: setLen on an uninitialized seq leaves the grown
      # slots' headers uninitialized under -d:danger.
      data = newSeq[seq[byte]](params.ecK)
      parity = newSeqWith(params.ecM, newSeqWith(params.blockSize.int, 0'u8))

    let (resolved, filledData) =
      ?await self.prepareEncodingData(
        originalTreeCid, params, step, move data, cids, params.emptyCid, emptyBlock
      )
    data = filledData

    trace "Erasure coding data", data = data.len
    # Encode on the taskpool: the structures are moved through the
    # spawnJoin result channel, no GC refs cross the boundary.
    try:
      parity =
        ?await spawnJoin(
          proc(ctx: SharedPtr[TaskCtx[seq[seq[byte]]]]) {.gcsafe, raises: [].} =
            self.taskPool.spawn leopardEncodeTask(
              ctx, addr self, params.blockSize.int, addr data, addr parity
            )
        )
    except SpawnContractError as e:
      return failure(e)
    var
      idx = params.rounded + step
      blocks: seq[(bt.Block, Natural, ?PrometheiProof)]

    for j in 0 ..< params.ecM:
      let blk = ?bt.Block.new(parity[j])

      trace "Adding parity block", cid = blk.cid, idx
      cids[idx] = blk.cid
      blocks.add((blk, idx.Natural, PrometheiProof.none))
      idx.inc(params.steps)

    trace "Storing parity blocks", count = blocks.len
    ?await self.networkStore.putBlocks(tmpTreeCid, blocks)

  trace "Encoding complete", encodedBlocksCount = params.encodedBlocksCount
  success cids

proc treeAndProofs*(
    self: Erasure, cids: ref seq[Cid], targetCid: Cid
): Future[?!Cid] {.async: (raises: [CancelledError]).} =
  ## Build a tree over `cids`, store per-leaf proofs under `targetCid`,
  ## and return the tree root.
  ##
  if cids[].len == 0:
    return failure "Empty leaves"

  proc liftCid(cid: Cid): Future[Cid] {.async.} =
    cid

  let cidsIter = mapAsync[Cid, Cid](Iter[Cid].new(cids[]), liftCid)
  defer:
    if err =? catchAsync(await cidsIter.dispose()).errorOption:
      warn "Failed to dispose tree iterator", err = err.msg

  let
    tree =
      ?await PrometheiTree.buildAsync(
        cidsIter, self.taskPool, mcodec = (?cids[][0].mhash.mapFailure).mcodec
      )
    treeCid = ?tree.rootCid

  var proofItems: seq[(Natural, Cid, PrometheiProof)]
  for index, cid in cids[]:
    proofItems.add((index.Natural, cid, ?tree.getProof(index)))

  ?await self.networkStore.putCidsAndProofs(targetCid, proofItems)

  trace "Tree and proofs stored", treeCid
  success treeCid

proc encode*(
    self: Erasure,
    manifest: Manifest,
    blocks: Natural,
    parity: Natural,
    strategy = SteppedStrategy,
): Future[?!Manifest] {.async: (raises: [CancelledError]).} =
  ## Encode a manifest into one that is erasure protected.
  ##
  ## `manifest`   - the original manifest to be encoded
  ## `blocks`     - the number of blocks to be encoded - K
  ## `parity`     - the number of parity blocks to generate - M
  ##

  let
    emptyCid = ?emptyCid(manifest.cidVersion, manifest.hcodec, manifest.codec)
    sourceManifest =
      if manifest.protected:
        Manifest.new(manifest)
      else:
        manifest
    params =
      ?EncodingParams.init(sourceManifest, blocks.int, parity.int, strategy, emptyCid)

  let treeCid =
    if manifest.protected:
      ?await self.repoStore.withOverlay(
        manifest.treeCid,
        status = Repairing.some,
        body = proc(): Future[?!Cid] {.
            closure, gcsafe, async: (raises: [CancelledError])
        .} =
          let cids =
            ?await self.encodeData(sourceManifest.treeCid, manifest.treeCid, params)
          await self.treeAndProofs(cids, manifest.treeCid)
        ,
      )
    else:
      ?await self.repoStore.withTmpOverlay(
        body = proc(
            tmpCid: Cid
        ): Future[?!Cid] {.closure, gcsafe, async: (raises: [CancelledError]).} =
          let cids = ?await self.encodeData(sourceManifest.treeCid, tmpCid, params)

          await self.treeAndProofs(cids, tmpCid)
      )

  let protected = Manifest.new(
    manifest = sourceManifest,
    treeCid = treeCid,
    ecK = blocks.int,
    ecM = parity.int,
    strategy = strategy,
    datasetSize = (sourceManifest.blockSize.int * params.encodedBlocksCount).NBytes,
  )

  success(protected)

proc leopardDecodeTask*(
    ctx: SharedPtr[TaskCtx[seq[seq[byte]]]],
    erasure: ptr Erasure,
    blockSize: int,
    blocks: ptr seq[seq[byte]],
    parity: ptr seq[seq[byte]],
) {.gcsafe, raises: [].} =
  # The borrows are raw pointers; recovered is created here and returned
  # through the result.
  let decoder = erasure.decoderProvider(blockSize, blocks[].len, parity[].len)
  defer:
    decoder.release()
    if err =? ctx[].signal.fireSync().errorOption:
      warn "Failed to fire worker completion signal", error = err

  var recovered = newSeqWith(blocks[].len, newSeqWith(blockSize, 0'u8))
  if (let res = decoder.decode(blocks[], parity[], recovered); res.isErr):
    warn "Error from leopard decoder backend!", error = $res.error
    ctx[].result = ThreadSpawnRes[seq[seq[byte]]].err($res.error)
  else:
    ctx[].result = ThreadSpawnRes[seq[seq[byte]]].ok(move recovered)

proc decodeStripes*(
    self: Erasure,
    data: sink seq[seq[byte]], # k shards; MISSING shards are empty seqs
    parity: sink seq[seq[byte]], # m parity shards; missing shards are empty seqs
): Future[?!seq[seq[byte]]] {.async: (raises: [CancelledError]).} =
  ## Decode one stripe: given the k data shards (missing shards passed as
  ## empty seqs) and any of the m parity shards (missing also empty), return
  ## all k data shards. At least k shards must be present. No storage, no
  ## CIDs, no source root.
  ##
  if data.len == 0:
    return failure "No shards to decode"

  var
    shardLen = 0
    pieces = 0
  for shard in data:
    if shard.len > 0:
      if shardLen == 0:
        shardLen = shard.len
      elif shard.len != shardLen:
        return failure "Mismatched shard lengths in decodeStripes"
      inc pieces
  for shard in parity:
    if shard.len > 0:
      if shardLen == 0:
        shardLen = shard.len
      elif shard.len != shardLen:
        return failure "Mismatched shard lengths in decodeStripes"
      inc pieces

  if shardLen == 0:
    return failure "No shards to decode"
  if pieces < data.len:
    return failure "Insufficient shards for decoding"

  var missing = false
  for shard in data:
    if shard.len == 0:
      missing = true

  if not missing:
    return success data # nothing to recover

  var
    d = data
    p = parity
    recovered: seq[seq[byte]]

  # Decode on the taskpool: the recovered data shards return through the
  # spawnJoin result channel, no GC refs cross the boundary.
  try:
    recovered =
      ?await spawnJoin(
        proc(ctx: SharedPtr[TaskCtx[seq[seq[byte]]]]) {.gcsafe, raises: [].} =
          self.taskPool.spawn leopardDecodeTask(
            ctx, addr self, shardLen, addr d, addr p
          )
      )
  except SpawnContractError as e:
    return failure(e)

  # leopard fills `recovered` only at erasure positions; the present
  # shards pass through unchanged
  for i in 0 ..< recovered.len:
    if d[i].len > 0:
      recovered[i] = move d[i]

  success recovered

proc decodeInternal(
    self: Erasure, encodedTreeCid: Cid, targetCid: Cid, params: EncodingParams
): Future[?!(ref seq[Cid], seq[Natural])] {.async: (raises: [CancelledError]).} =
  logScope:
    encodedTreeCid = encodedTreeCid
    targetCid = targetCid
    steps = params.steps
    roundedBlocks = params.rounded
    encodedBlocksCount = params.encodedBlocksCount

  var
    cids = seq[Cid].new()
    recoveredIndices = newSeq[Natural]()
    emptyBlock = newSeqWith(params.blockSize.int, 0xFF'u8)

  cids[].setLen(params.encodedBlocksCount)
  for step in 0 ..< params.steps:
    var
      # Fresh payloads: setLen on an uninitialized seq leaves the grown
      # slots' headers uninitialized under -d:danger.
      data = newSeq[seq[byte]](params.ecK)
      parityData = newSeq[seq[byte]](params.ecM)
      recovered: seq[seq[byte]]
    let (dataPieces, parityPieces, filledData, filledParity) =
      ?await self.prepareDecodingData(
        encodedTreeCid, params, step, move data, move parityData, cids, emptyBlock
      )
    data = filledData
    parityData = filledParity

    if dataPieces + parityPieces < params.ecK:
      return failure(
        (ref InsufficientBlocksError)(
          msg:
            "Insufficient erasure pieces for decoding step " & $step & ": got " &
            $(dataPieces + parityPieces) & ", need " & $params.ecK
        )
      )

    if dataPieces >= params.ecK:
      trace "Retrieved all the required data blocks"
      continue

    trace "Erasure decoding data"
    # Decode on the taskpool: data stays a caller-side borrow (read after
    # the await), the recovered blocks return through the result channel.
    try:
      recovered =
        ?await spawnJoin(
          proc(ctx: SharedPtr[TaskCtx[seq[seq[byte]]]]) {.gcsafe, raises: [].} =
            self.taskPool.spawn leopardDecodeTask(
              ctx, addr self, params.blockSize.int, addr data, addr parityData
            )
        )
    except SpawnContractError as e:
      return failure(e)
    var blocks: seq[(bt.Block, Natural, ?PrometheiProof)]
    for i in 0 ..< params.ecK:
      let idx = i * params.steps + step
      if data[i].len <= 0 and not cids[idx].isEmpty:
        without blk =? bt.Block.new(recovered[i]), error:
          trace "Unable to create block!", exc = error.msg
          return failure(error)

        trace "Recovered block", cid = blk.cid, index = i
        await self.networkStore.completeBlock(encodedTreeCid, idx, blk)

        cids[idx] = blk.cid
        blocks.add((blk, idx.Natural, PrometheiProof.none))
        recoveredIndices.add(idx)

    trace "Storing recovered blocks", count = blocks.len
    ?await self.repoStore.putBlocks(targetCid, blocks)

  return (cids, recoveredIndices).success

proc decode*(
    self: Erasure, encoded: Manifest, fetchFrom = Cid.none
): Future[?!Manifest] {.async: (raises: [CancelledError]).} =
  ## Decode a protected manifest into it's original
  ## manifest
  ##
  ## `encoded` - the encoded (protected) manifest to
  ##             be recovered
  ##
  ## `fetchFrom` - root to fetch the encoded shards from, when it differs
  ##             from `encoded.treeCid` (a verifiable dataset's shards are
  ##             served under the verifiable root).
  ##

  logScope:
    treeCid = encoded.treeCid
    originalTreeCid = encoded.originalTreeCid

  trace "Preparing to decode dataset"

  let
    emptyCid = ?emptyCid(encoded.cidVersion, encoded.hcodec, encoded.codec)
    params = EncodingParams.initFromEncoded(encoded, emptyCid)
    fetchRoot = fetchFrom |? encoded.treeCid

  var
    cids: ref seq[Cid]
    recoveredIndices: seq[Natural]

  ?await self.repoStore.withOverlay(
    encoded.originalTreeCid,
    status = Storing.some,
    body = proc(): Future[?!void] {.closure, async: (raises: [CancelledError]).} =
      let
        (cids, recoveredIndices) =
          ?await self.decodeInternal(fetchRoot, encoded.originalTreeCid, params)
        tree =
          # sync build: root comparison only (decode paths do not stream)
          ?PrometheiTree.init(cids[0 ..< encoded.originalBlocksCount])
        treeCid = ?tree.rootCid

      if treeCid != encoded.originalTreeCid:
        return failure(
          "Original tree root differs from the tree root computed out of recovered data"
        )

      let idxIter =
        Iter[Natural].new(recoveredIndices).filter((i: Natural) => i < tree.leavesCount)

      if err =? (await self.repoStore.putSomeProofs(tree, idxIter)).errorOption:
        return failure(err)

      trace "Successfully decoded original dataset"
      success(),
  )

  let decoded = Manifest.new(encoded)
  return decoded.success

proc repair*(
    self: Erasure, encoded: Manifest, fetchFrom = Cid.none
): Future[?!void] {.async: (raises: [CancelledError]).} =
  ## Repair a protected manifest by reconstructing the full dataset
  ##
  ## `encoded` - the encoded (protected) manifest to
  ##             be repaired
  ##
  ## `fetchFrom` - root to fetch the encoded shards from, when it differs
  ##             from `encoded.treeCid`. A provider repairing a slot of a
  ##             verifiable dataset can only fetch (and prove) under the
  ##             verifiable root - the protected tree's blocks are its
  ##             prefix at identical indices - while reconstruction and
  ##             re-encoding stay addressed by `encoded`.
  ##
  ## TODO: there are several quirks to be aware of here -
  ## decode can only recreate original blocks, the resulting
  ## parity is not usable (AFAIK) as the original parity blocks
  ## so we need decode the original dataset first and then
  ## re-encode it to get valid parity blocks for the repaired manifest
  ##
  ## So the first decode is called with the original tree as it's overlay,
  ## the call to encode will create the protected overlay and manifest,
  ## this means that we need to properly handle cleanup of these overlays
  ## to avoid leaving garbage in the store
  ##

  logScope:
    treeCid = encoded.treeCid
    originalTreeCid = encoded.originalTreeCid
    fetchFrom = fetchFrom

  trace "Preparing to repair dataset"

  let
    emptyCid = ?emptyCid(encoded.cidVersion, encoded.hcodec, encoded.codec)
    params = EncodingParams.initFromEncoded(encoded, emptyCid)
    fetchRoot = fetchFrom |? encoded.treeCid

  ?await self.repoStore.withOverlay(
    encoded.originalTreeCid,
    status = Repairing.some,
    body = proc(): Future[?!void] {.closure, async: (raises: [CancelledError]).} =
      let
        (cids, _) =
          ?await self.decodeInternal(fetchRoot, encoded.originalTreeCid, params)
        tree =
          # sync build: root comparison only (decode paths do not stream)
          ?PrometheiTree.init(cids[0 ..< encoded.originalBlocksCount])
        treeCid = ?tree.rootCid

      if treeCid != encoded.originalTreeCid:
        return failure(
          "Original tree root differs from the tree root computed out of recovered data"
        )

      ?await self.repoStore.putAllProofs(tree)
      trace "Successfully repaired original dataset"
      success(),
  )

  # TODO: We don't get valid parity data from leopard,
  # so we need to do full re-encoding to get parity
  # blocks for a valid slot - this is higly inneficient
  # we need to either fix leopard or use another implementation
  let repaired =
    ?(await self.encode(encoded, encoded.ecK, encoded.ecM, encoded.protectedStrategy))

  trace "Successfully re-encoded original dataset"
  if repaired.treeCid != encoded.treeCid:
    return failure(
      "Original tree root differs from the repaired tree root encoded out of recovered data"
    )

  return success()

proc start*(self: Erasure) {.async.} =
  return

proc stop*(self: Erasure) {.async.} =
  return

proc new*(
    T: type Erasure,
    networkStore: BlockStore,
    repoStore: RepoStore,
    encoderProvider: EncoderProvider,
    decoderProvider: DecoderProvider,
    taskPool: Taskpool,
): Erasure =
  ## Create a new Erasure instance for encoding and decoding manifests
  ##
  Erasure(
    networkStore: networkStore,
    repoStore: repoStore,
    encoderProvider: encoderProvider,
    decoderProvider: decoderProvider,
    taskPool: taskPool,
  )
