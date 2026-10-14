import pkg/chronos

import promethei/utils/timer

type MockTimer* = ref object of Timer
  startCalled*: int
  stopCalled*: int
  mockInterval*: Duration
  mockCallback: timer.TimerCallback

proc new*(T: type MockTimer): MockTimer =
  ## Create a mocked Timer instance
  MockTimer(startCalled: 0, stopCalled: 0)

method start*(mockTimer: MockTimer, callback: timer.TimerCallback, interval: Duration) =
  mockTimer.mockCallback = callback
  mockTimer.mockInterval = interval
  inc mockTimer.startCalled

method stop*(mockTimer: MockTimer) {.async: (raises: []).} =
  inc mockTimer.stopCalled

method invokeCallback*(mockTimer: MockTimer) {.async, base.} =
  await mockTimer.mockCallback()
