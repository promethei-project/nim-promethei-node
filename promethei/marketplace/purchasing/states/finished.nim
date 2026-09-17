import pkg/metrics

import ../statemachine
import ../../../utils/exceptions
import ../../../logutils
import ./types

declareCounter(promethei_purchases_finished, "promethei purchases finished")

logScope:
  topics = "marketplace purchases finished"

method `$`*(state: PurchaseFinished): string =
  "finished"

method run*(
    state: PurchaseFinished, machine: Machine
): Future[?State] {.async: (raises: []).} =
  promethei_purchases_finished.inc()
  let purchase = Purchase(machine)
  try:
    info "Purchase finished, withdrawing remaining funds",
      requestId = purchase.requestId
    await purchase.marketplace.withdrawFunds(purchase.requestId)

    purchase.future.complete()
  except CancelledError as e:
    trace "PurchaseFinished.run was cancelled", error = e.msgDetail
  except CatchableError as e:
    error "Error during PurchaseFinished.run", error = e.msgDetail
    return some State(PurchaseErrored(error: e))
