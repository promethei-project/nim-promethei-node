{.push raises: [].}

import pkg/chronos
import pkg/questionable/results

proc settleSlotFutures*[T](
    futures: seq[Future[?!T]]
): Future[?!void] {.async: (raises: [CancelledError]).} =
  var
    firstError: ref CatchableError
    cancelled = false

  proc cancelAndJoin() {.async: (raises: []).} =
    for future in futures:
      if not future.finished:
        await noCancel future.cancelAndWait()

  try:
    await allFutures(futures)
  except CancelledError as exc:
    await cancelAndJoin()
    raise exc

  for future in futures:
    if future.cancelled:
      cancelled = true
    elif future.failed:
      if firstError.isNil:
        firstError = future.error
    else:
      let res = future.value
      if res.isErr and firstError.isNil:
        firstError = res.error

  if cancelled:
    raise newException(CancelledError, "Slot build was cancelled")
  if not firstError.isNil:
    return failure(firstError)
  success()
