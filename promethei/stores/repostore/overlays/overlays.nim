## Overlay metadata operations - storing, retrieving, and listing dataset overlays

{.push raises: [].}

import std/algorithm
import std/tables

import pkg/chronos
import pkg/kvstore
import pkg/libp2p/[cid, multihash, multicodec]
import pkg/stew/bitseqs
import pkg/results
import pkg/questionable
import pkg/questionable/results

import ./coders
import ../types
import ../operations
import ../treeops
import ../../keyutils
import ../../../clock
import ../../../prometheitypes

import ../../queryiterhelper

import ../../../utils
import ../../../errors
import ../../../logutils
import ../../../rng

export coders

logScope:
  topics = "promethei repostore overlays"

proc mergeOverlay(
    self: RepoStore,
    overlay: var OverlayMetadata,
    status: ?OverlayStatus,
    blocks: BitSeq,
    expiry: SecondsSince1970,
    manifestCid: ?Cid,
) =
  ## Apply merge logic: OR-combine blocks, fallback status, conditional fields.
  ##

  overlay.blocks.combineSafe(blocks)
  overlay.status = status |? overlay.status

  if manifestCid.isSome:
    overlay.manifestCid = manifestCid

  if expiry != ZeroSeconds:
    overlay.expiry = expiry
  elif overlay.expiry == ZeroSeconds:
    overlay.expiry = self.clock.now() + self.overlayTtl

proc putOverlay*(
    self: RepoStore,
    treeCid: Cid,
    status: ?OverlayStatus = OverlayStatus.none,
    blocks = BitSeq.init(0),
    expiry = ZeroSeconds,
    manifestCid: ?Cid = Cid.none,
): Future[?!void] {.async: (raises: [CancelledError]).} =
  ## Store overlay metadata with CAS semantics (upsert).
  ## On conflict, re-reads current state and merges with provided values
  ## instead of blindly overwriting.
  ##
  ## Parameters:
  ## - status: OverlayStatus to set (uses |? fallback if not provided)
  ## - blocks: BitSeq to OR-combine with existing
  ## - expiry: Expiry time (sets if non-zero, otherwise keeps existing or sets default)
  ## - manifestCid: Optional manifest CID to set
  ##

  let key = ?overlayKey(treeCid)
  self.overlayCache.del(key)

  # Read full KVRecord (preserving CAS token) for correct first attempt
  without var record =? (await self.metaDs.get(key, OverlayMetadata)), err:
    if not (err of KVStoreKeyNotFound):
      trace "Error fetching overlay metadata for put",
        treeCid = treeCid, error = err.msg
      return failure(err)
    record = KVRecord[OverlayMetadata].init(key, OverlayMetadata())

  # Deleting and Finalizing overlays reject ordinary writes, including
  # expiry-only updates: a finalization in flight must not be overwritten.
  if overlayRejectsWrites(record.val.status):
    return failure(
      newException(OverlayDeletingError, "Overlay is finalizing or deleting")
    )

  self.mergeOverlay(record.val, status, blocks, expiry, manifestCid)
  var cachedOverlay = record.val
  ?await self.metaDs.tryPut(
    record,
    maxRetries = 10,
    proc(
        failed: seq[KVRecord[OverlayMetadata]]
    ): Future[?!seq[KVRecord[OverlayMetadata]]] {.async: (raises: [CancelledError]).} =
      var records = ?await self.metaDs.get(failed.mapIt(it.key), OverlayMetadata)
      for rec in records.mitems:
        if overlayRejectsWrites(rec.val.status):
          return failure(
            newException(OverlayDeletingError, "Overlay is finalizing or deleting")
          )
      self.mergeOverlay(records[0].val, status, blocks, expiry, manifestCid)
      cachedOverlay = records[0].val
      success records
    ,
  )

  # cache the final merged overlay
  self.overlayCache[key] = cachedOverlay
  if cachedOverlay.status != Completed:
    self.treeShapeCache.del(treeCid)
  trace "Overlay metadata stored", treeCid = treeCid, status = cachedOverlay.status
  success()

proc getOverlay*(
    self: RepoStore, treeCid: Cid
): Future[?!OverlayMetadata] {.async: (raises: [CancelledError]).} =
  ## Get overlay metadata for a dataset.
  ##

  let key = ?overlayKey(treeCid)
  self.overlayCache.withValue(key, value):
    return success value[]

  let meta = ?await self.metaDs.get(key, OverlayMetadata)
  trace "OverlayMetadata loaded", treeCid = treeCid, status = meta.val.status

  success meta.val

proc deleteOverlay*(
    self: RepoStore, treeCid: Cid
): Future[?!void] {.async: (raises: [CancelledError]).} =
  ## Delete overlay metadata
  ##

  let key = ?overlayKey(treeCid)
  self.overlayCache.del(key)

  ?await self.metaDs.delete(?await self.metaDs.get(key))

  trace "Overlay metadata deleted", treeCid = treeCid
  success()

func toCid(key: Key): ?!Cid =
  success ?Cid.init(key.value).mapFailure

proc listOverlays*(
    self: RepoStore
): Future[?!AsyncIter[Cid]] {.async: (raises: [CancelledError]).} =
  ## List all overlay CIDs.
  ##

  let
    queryKey = ?overlayQueryKey()
    iter = ?(await query(self.metaDs, Query.init(queryKey), OverlayMetadata))

  let queryIter = iter.toAsyncIter()

  let mapCids = proc(
      iterRes: ?!(?KVRecord[OverlayMetadata])
  ): Future[Option[Cid]] {.async.} =
    if maybeRecord =? iterRes and record =? maybeRecord:
      without cid =? record.key.toCid, err:
        trace "Unable to construct Cid from key", error = err.msg
        return none(Cid)
      return some(cid)
    return none(Cid)

  success await mapFilter[?!(?KVRecord[OverlayMetadata]), Cid](queryIter, mapCids)

proc listOverlaysInState*(
    self: RepoStore, status: OverlayStatus
): Future[?!AsyncIter[Cid]] {.async: (raises: [CancelledError]).} =
  ## List all overlay CIDs by status.
  ##

  let
    queryKey = ?overlayQueryKey()
    iter = ?(await query(self.metaDs, Query.init(queryKey), OverlayMetadata))

  let queryIter = iter.toAsyncIter()

  let filterByStatus = proc(
      iterRes: ?!(?KVRecord[OverlayMetadata])
  ): Future[Option[Cid]] {.async.} =
    if maybeRecord =? iterRes and record =? maybeRecord:
      if record.val.status == status:
        without cid =? record.key.toCid, err:
          trace "Unable to construct Cid from key", error = err.msg
          return none(Cid)

        return some(cid)

    return none(Cid)

  success await mapFilter[?!(?KVRecord[OverlayMetadata]), Cid](
    queryIter, filterByStatus
  )

proc listOverlaysByExpiry*(
    self: RepoStore, limit: int, offset: int
): Future[?!seq[(Cid, OverlayMetadata)]] {.async: (raises: [CatchableError]).} =
  ## List overlays sorted by expiry time (ascending).
  ##

  let
    queryKey = ?overlayQueryKey()
    iter =
      ?(
        await query(
          self.metaDs,
          Query.init(queryKey, limit = limit, offset = offset),
          OverlayMetadata,
        )
      )

  let queryIter = iter.toAsyncIter()

  let mapRecord = proc(
      iterRes: ?!(?KVRecord[OverlayMetadata])
  ): Future[Option[(Cid, OverlayMetadata)]] {.async.} =
    if maybeRecord =? iterRes and record =? maybeRecord:
      without cid =? record.key.toCid, err:
        trace "Unable to construct Cid from key", error = err.msg
        return none((Cid, OverlayMetadata))

      return some((cid, record.val))

    return none((Cid, OverlayMetadata))

  let mapped = await mapFilter[?!(?KVRecord[OverlayMetadata]), (Cid, OverlayMetadata)](
    queryIter, mapRecord
  )
  let metadata = (await collectAsync(mapped))
  # Sort by expiry (ascending - earliest expiry first)
  .sorted(
    func (a, b: (Cid, OverlayMetadata)): int =
      cmp(a[1].expiry, b[1].expiry)
  )

  success metadata

proc createTmpOverlay*(
    self: RepoStore, expiry = ZeroSeconds
): Future[?!Cid] {.async: (raises: [CancelledError]).} =
  var randomBytes: array[32, byte]
  Rng.instance[].generate(randomBytes)
  let
    mhash = ?MultiHash.digest($Sha256HashCodec, randomBytes).mapFailure
    tmpTreeCid = ?Cid.init(CIDv1, BlockCodec, mhash).mapFailure

  let expiryTime =
    if expiry == ZeroSeconds:
      self.clock.now() + self.overlayTtl
    else:
      expiry

  ?await self.putOverlay(
    tmpTreeCid,
    status = OverlayStatus.Storing.some,
    blocks = BitSeq.init(0),
    expiry = expiryTime,
  )

  success tmpTreeCid

proc dropOverlay*(
    self: RepoStore, treeCid: Cid
): Future[?!void] {.async: (raises: [CancelledError]).} =
  ## Drop an overlay and delete all attached blocks.
  ##
  ## Queries all leaf records under /meta/leafs/{treeCid}/*, calls
  ## delLeafBlockMetadata to decrement refcounts and delete blocks at
  ## refCount=0, then deletes the overlay metadata record.
  ##
  ## Uses a runtime lock to prevent concurrent deletions of the same
  ## overlay. Returns success if deletion is already in progress.
  ##

  logScope:
    treeCid = treeCid

  trace "Dropping overlay and cleaning up blocks"

  without overlay =? (await self.getOverlay(treeCid)), err:
    if err of KVStoreKeyNotFound:
      trace "Overlay already deleted", treeCid
      return success()
    return failure(err)

  if overlay.status == Finalizing:
    return failure(newException(OverlayDeletingError, "Overlay is finalizing"))

  if err =? (await self.markDeleting(treeCid)).errorOption:
    error "Unable to mark overlay as deleting", exc = err.msg
    return failure(err)

  await self.deletingLock.drain(treeCid)

  while true:
    without overlay =? (await self.getOverlay(treeCid)), err:
      if err of KVStoreKeyNotFound:
        trace "Overlay already deleted", treeCid
        break
      warn "Overlay missing", treeCid, err = err.msg
      return failure(err)

    var indices: seq[Natural]
    for i in 0 ..< overlay.blocks.len:
      if overlay.blocks[i.Natural]:
        indices.add(i.Natural)

    # Delete leaf metadata and decrement refcounts (two-phase atomic)
    if indices.len == 0:
      break

    ?await self.delLeafBlockMetadata(treeCid, indices)
    trace "Deleted leaf metadata and updated refcounts", count = indices.len

  ?await self.delTreeNodes(treeCid)
  self.treeShapeCache.del(treeCid)

  # Detach manifest and try to delete if refcount reaches 0
  ?await self.dropManifest(treeCid)

  # Delete overlay metadata
  ?await self.deleteOverlay(treeCid)
  self.treeShapeCache.del(treeCid)

  trace "Overlay dropped successfully"

  success()

proc finishFinalizing(
    self: RepoStore, treeCid: Cid, status: OverlayStatus, expiry = ZeroSeconds
): Future[?!void] {.async: (raises: [CancelledError]).} =
  ## Complete a publication or restore a temporary overlay. The stored status
  ## must be Finalizing on the initial read and on every CAS retry; only
  ## finalization may transition out of it. A `ZeroSeconds` expiry keeps the
  ## stored value, which moved metadata already carries.
  ##

  let key = ?overlayKey(treeCid)
  self.overlayCache.del(key)

  without var record =? (await self.metaDs.get(key, OverlayMetadata)), err:
    return failure(err)

  if record.val.status != Finalizing:
    return failure(newException(OverlayDeletingError, "Overlay is not finalizing"))

  record.val.status = status
  if expiry != ZeroSeconds:
    record.val.expiry = expiry
  var cached = record.val

  ?await self.metaDs.tryPut(
    record,
    maxRetries = 10,
    proc(
        failed: seq[KVRecord[OverlayMetadata]]
    ): Future[?!seq[KVRecord[OverlayMetadata]]] {.async: (raises: [CancelledError]).} =
      var records = ?await self.metaDs.get(failed.mapIt(it.key), OverlayMetadata)
      for rec in records.mitems:
        if rec.val.status != Finalizing:
          return
            failure(newException(OverlayDeletingError, "Overlay is not finalizing"))
        rec.val.status = status
        if expiry != ZeroSeconds:
          rec.val.expiry = expiry
      cached = records[0].val
      success records
    ,
  )

  self.overlayCache[key] = cached
  self.treeShapeCache.del(treeCid)
  success()

proc finalizeOverlay*(
    self: RepoStore,
    tmpCid, realTreeCid: Cid,
    status = OverlayStatus.none,
    expiry = ZeroSeconds,
): Future[?!void] {.async: (raises: []).} =
  ## Promote a temp overlay to a real overlay.
  ##
  ## Atomically moves leaf records, tree records, and overlay metadata from
  ## tmpCid to realTreeCid. The tmp overlay is marked Finalizing before
  ## the move to reject concurrent writers, and the destination carries the
  ## final status before it becomes writable again.
  ##
  ## Publication (or its compensation) runs to completion: caller
  ## cancellation is deferred until the namespace is consistent.
  ##

  logScope:
    tmpCid = tmpCid
    realTreeCid = realTreeCid

  trace "Finalizing temp overlay"

  let
    tmpOverlayKey = ?overlayKey(tmpCid)
    overlayKey = ?overlayKey(realTreeCid)

  defer:
    self.overlayCache.del(tmpOverlayKey)
    self.treeShapeCache.del(tmpCid)
    self.overlayCache.del(overlayKey)
    self.treeShapeCache.del(realTreeCid)

  # Read original status, mark Finalizing (rejects new writers), drain in-flight writers.
  without tmpRecord =?
      (await noCancel(self.metaDs.get(tmpOverlayKey, OverlayMetadata))),
    err:
    return failure(err)
  let tmpOrigStatus = tmpRecord.val.status

  if err =? (await noCancel(self.markFinalizing(tmpCid))).errorOption:
    return failure(err)

  await noCancel(self.deletingLock.drain(tmpCid))

  let expiryTime =
    if expiry == ZeroSeconds:
      self.clock.now() + self.overlayTtl
    else:
      expiry

  # Atomically move leaf records, tree records, and overlay metadata.
  # The overlay carries Finalizing status during the move.
  if err =? (
    await noCancel(
      self.metaDs.moveKeysAtomic(
        @[
          (?(BlockLeafKey / $tmpCid), ?(BlockLeafKey / $realTreeCid)),
          (?(TreeNodeKey / $tmpCid), ?(TreeNodeKey / $realTreeCid)),
          (tmpOverlayKey, overlayKey),
        ]
      )
    )
  ).errorOption:
    if restoreErr =?
        (await noCancel(self.finishFinalizing(tmpCid, tmpOrigStatus))).errorOption:
      error "Unable to restore tmp overlay after finalization failure",
        exc = restoreErr.msg
      return failure(restoreErr)
    error "Unable to move overlay metadata atomically", exc = err.msg
    return failure(err)

  # Set final status at realTreeCid. The overlay arrived as Finalizing,
  # so no writers can race.
  let finalStatus = status |? tmpOrigStatus
  if err =? (
    await noCancel(self.finishFinalizing(realTreeCid, finalStatus, expiryTime))
  ).errorOption:
    error "Unable to set final overlay status after finalization", exc = err.msg

    # The destination is still Finalizing and rejects ordinary writes;
    # reverse the move so the temporary namespace is usable again.
    if inverseErr =? (
      await noCancel(
        self.metaDs.moveKeysAtomic(
          @[
            (?(BlockLeafKey / $realTreeCid), ?(BlockLeafKey / $tmpCid)),
            (?(TreeNodeKey / $realTreeCid), ?(TreeNodeKey / $tmpCid)),
            (overlayKey, tmpOverlayKey),
          ]
        )
      )
    ).errorOption:
      error "Unable to reverse namespace move after finalization failure",
        exc = inverseErr.msg, original = err.msg
      return failure(inverseErr)

    if restoreErr =?
        (await noCancel(self.finishFinalizing(tmpCid, tmpOrigStatus))).errorOption:
      error "Unable to restore tmp overlay after reversed finalization",
        exc = restoreErr.msg, original = err.msg
      return failure(restoreErr)

    error "Finalization failed and the temporary namespace was restored",
      exc = err.msg
    return failure(err)

  trace "Temp overlay finalized successfully"
  success()

proc withOverlay*[T](
    self: RepoStore,
    treeCid: Cid,
    status = OverlayStatus.none,
    expiry = ZeroSeconds,
    body: proc(): Future[?!T] {.closure, gcsafe, async: (raises: [CancelledError]).},
): Future[?!T] {.async: (raises: [CancelledError]).} =
  ## Create or update overlay with initial state and expiry.
  ##

  logScope:
    treeCid = treeCid
    status = status

  trace "Starting overlay operation"
  if err =? (await self.putOverlay(treeCid, status, BitSeq.init(0), expiry)).errorOption:
    error "Unable to create/update overlay metadata", exc = err.msg
    return failure(err)

  let
    bodyRes = await body()
    finalState = if bodyRes.isOk: Completed.some else: Failure.some

  if err =?
      (await self.putOverlay(treeCid, finalState, BitSeq.init(0), expiry)).errorOption:
    error "Unable to set overlay final state", exc = err.msg
    return failure(err)

  trace "Overlay operation completed", finalState

  return bodyRes

proc withTmpOverlay*(
    self: RepoStore,
    body: proc(tmpCid: Cid): Future[?!Cid] {.
      closure, gcsafe, async: (raises: [CancelledError])
    .},
): Future[?!Cid] {.async: (raises: [CancelledError]).} =
  ## Create a temporary overlay, run body, finalize or drop.
  ## Body must return ?!Cid (the real treeCid).
  ##

  trace "Starting temporary overlay operation"

  var completed = false

  without tmpCid =? (await self.createTmpOverlay()), err:
    error "Unable to create temporary overlay", exc = err.msg
    return failure(err)

  trace "Temporary overlay created", tmpCid

  defer:
    if not completed:
      # Tmp overlays have no refcount associations yet - safe to drop directly
      if dropErr =? (await noCancel self.dropOverlay(tmpCid)).errorOption:
        error "Unable to drop tmp overlay on error", exc = dropErr.msg

  let bodyRes = await body(tmpCid)

  without realCid =? bodyRes, err:
    error "Body failed to return real tree CID", error = err.msg
    return failure(err)

  trace "Body completed successfully, finalizing overlay", realCid, tmpCid
  # Finalization is not cancellable: it owns its cancel schedule, so
  # cancelling this operation cannot abort between markFinalizing and the
  # atomic key move. The defer above then sees the tmp overlay already
  # moved (or deleted) and drops it as a no-op.
  if finalErr =? (
    await self.finalizeOverlay(tmpCid, realCid, status = OverlayStatus.Completed.some)
  ).errorOption:
    error "Unable to finalize tmp overlay", exc = finalErr.msg
    return failure(finalErr)

  completed = true
  bodyRes
