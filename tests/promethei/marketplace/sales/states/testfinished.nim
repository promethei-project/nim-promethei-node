import pkg/questionable
import pkg/promethei/marketplace/contracts/requests
import pkg/promethei/marketplace/sales/states/finished
import pkg/promethei/marketplace/sales/states/cancelled
import pkg/promethei/marketplace/sales/states/failed
import pkg/promethei/marketplace/sales/salesagent
import pkg/promethei/marketplace/sales/salescontext
import pkg/promethei/marketplace/abstractmarketplace

import ../../../../asynctest
import ../../../examples
import ../../../helpers
import ../../../helpers/mockmarketplace
import ../../../helpers/mockclock

asyncchecksuite "sales state 'finished'":
  let request = StorageRequest.example
  let slotIndex = request.ask.slots div 2
  let slot = Slot(request: request, slotIndex: slotIndex)
  let clock = MockClock.new()

  var marketplace: MockMarketplace
  var state: SaleFinished
  var agent: SalesAgent
  var reprocessSlotWas = bool.none

  setup:
    marketplace = MockMarketplace.new()
    let onCleanUp = proc(reprocessSlot = false) {.async: (raises: []).} =
      reprocessSlotWas = some reprocessSlot

    let context = SalesContext(marketplace: marketplace, clock: clock)
    agent = newSalesAgent(context, SlotInfo.init(slot.id))
    agent.onCleanUp = onCleanUp
    state = SaleFinished()

  test "switches to cancelled state when request expires":
    let next = state.onCancelled(request)
    check !next of SaleCancelled

  test "switches to failed state when request fails":
    let next = state.onFailed(request)
    check !next of SaleFailed

  test "calls onCleanUp with reprocessSlot = true":
    discard await state.run(agent)
    check eventually reprocessSlotWas == some false
