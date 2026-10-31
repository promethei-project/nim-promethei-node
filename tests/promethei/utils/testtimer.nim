import pkg/chronos

import promethei/utils/timer

import ../../asynctest
import ../helpers

asyncchecksuite "Timer":
  var timer1: Timer
  var timer2: Timer
  var output: string
  var numbersState = 0
  var lettersState = 'a'

  proc numbersCallback(): Future[void] {.async: (raises: []).} =
    output &= $numbersState
    inc numbersState

  proc lettersCallback(): Future[void] {.async: (raises: []).} =
    output &= $lettersState
    inc lettersState

  proc startNumbersTimer() =
    timer1.start(numbersCallback, 10.milliseconds)

  proc startLettersTimer() =
    timer2.start(lettersCallback, 10.milliseconds)

  setup:
    timer1 = Timer.new("testtimer1")
    timer2 = Timer.new("testtimer2")

    output = ""
    numbersState = 0
    lettersState = 'a'

  teardown:
    await timer1.stop()
    await timer2.stop()

  test "Start timer1 should execute callback":
    startNumbersTimer()
    check eventually(output == "0", pollInterval = 10)

  test "Start timer1 should execute callback multiple times":
    startNumbersTimer()
    check eventually(output == "012", pollInterval = 10)

  test "Starting timer1 multiple times has no impact":
    startNumbersTimer()
    startNumbersTimer()
    startNumbersTimer()
    check eventually(output == "01234", pollInterval = 10)

  test "Stop timer1 should stop execution of the callback":
    startNumbersTimer()
    check eventually(output == "012", pollInterval = 10)
    await timer1.stop()
    await sleepAsync(30.milliseconds)
    let stoppedOutput = output
    await sleepAsync(30.milliseconds)
    check output == stoppedOutput

  test "Starting both timers should execute callbacks sequentially":
    startNumbersTimer()
    startLettersTimer()
    check eventually(output == "0a1b2c3d4e", pollInterval = 10)

  test "Stopping a timer that was never started completes":
    await timer2.stop()

  test "Stopping twice is idempotent":
    startNumbersTimer()
    check eventually(output == "0", pollInterval = 10)
    await timer1.stop()
    await timer1.stop()

  test "Timer can be started again after it was stopped":
    startNumbersTimer()
    check eventually(output == "0", pollInterval = 10)
    await timer1.stop()
    let stoppedLength = output.len
    startNumbersTimer()
    check eventually(output.len > stoppedLength, pollInterval = 10)

  test "Stop completes when the callback swallows cancellation":
    # BlockMaintainer's callback catches CancelledError and returns normally, so
    # a stop that arrives while it runs must still complete and the loop must not
    # invoke the callback again. The stop future is never awaited directly: on a
    # regression it never completes, and awaiting it would hang the whole suite
    # instead of failing this test.
    var invocations = 0

    proc callback(): Future[void] {.async: (raises: []).} =
      inc invocations
      try:
        await sleepAsync(50.milliseconds)
      except CancelledError:
        discard

    let timer = Timer.new("testtimer-stop-during-callback")
    timer.start(callback, 20.milliseconds)
    check eventually(invocations >= 1, pollInterval = 10)

    let stopping = timer.stop()
    let invocationsAtStop = invocations
    await sleepAsync(300.milliseconds)

    check stopping.finished
    check invocations == invocationsAtStop
