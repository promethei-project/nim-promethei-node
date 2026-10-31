## Timer
## Used to execute a callback in a loop

{.push raises: [].}

import pkg/chronos

import ../logutils

type
  TimerCallback* = proc(): Future[void] {.gcsafe, async: (raises: []).}
  Timer* = ref object of RootObj
    callback: TimerCallback
    interval: Duration
    name: string
    loopFuture: Future[void]
    stopRequested: bool

proc new*(T: type Timer, timerName: string): Timer =
  ## Create a new Timer intance with the given name
  Timer(name: timerName)

proc timerLoop(timer: Timer) {.async: (raises: []).} =
  try:
    while not timer.stopRequested:
      await timer.callback()
      # The callback may swallow the cancellation it receives (callbacks are
      # declared raising no exceptions), so check whether a stop was requested
      # while it ran, otherwise the loop would resume and never complete.
      if timer.stopRequested:
        break
      await sleepAsync(timer.interval)
  except CancelledError:
    discard # do not propagate as timerLoop is asyncSpawned
  except CatchableError as err:
    error "CatchableError in timer loop", name = timer.name, msg = err.msg
  info "Timer loop has stopped", name = timer.name

method start*(
    timer: Timer, callback: TimerCallback, interval: Duration
) {.gcsafe, base.} =
  if timer.loopFuture != nil:
    return
  trace "Timer starting: ", name = timer.name
  timer.callback = callback
  timer.interval = interval
  timer.stopRequested = false
  timer.loopFuture = timerLoop(timer)

method stop*(timer: Timer) {.base, async: (raises: []).} =
  timer.stopRequested = true
  if timer.loopFuture != nil and not timer.loopFuture.finished:
    trace "Timer stopping: ", name = timer.name
    await timer.loopFuture.cancelAndWait()
  timer.loopFuture = nil
