import std/hashes
import std/sequtils
import pkg/stew/endians2

import message

import ../../blocktype

export Message, encode, decode, messageKind
export Wantlist, WantType, WantListEntry
export BlockDelivery, BlockPresenceType, BlockPresence

proc hash*(a: BlockAddress): Hash =
  if a.leaf:
    let data = a.treeCid.data.buffer & @(a.index.uint64.toBytesBE)
    hash(data)
  else:
    hash(a.cid.data.buffer)

proc hash*(e: WantListEntry): Hash =
  hash(e.address)

proc contains*(a: openArray[WantListEntry], b: BlockAddress): bool =
  ## Convenience method to check for peer precense
  ##

  a.anyIt(it.address == b)

proc `==`*(a: WantListEntry, b: BlockAddress): bool =
  return a.address == b

proc `<`*(a, b: WantListEntry): bool =
  a.priority < b.priority

proc `==`*(a: BlockPresence, b: BlockAddress): bool =
  return a.address == b

proc contains*(a: openArray[BlockPresence], b: BlockAddress): bool =
  ## Convenience method to check for peer precense
  ##

  a.anyIt(it.address == b)
