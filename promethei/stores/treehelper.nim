{.push raises: [].}

import std/sugar

import pkg/iter
import pkg/chronos
import pkg/chronos/futures
import pkg/metrics
import pkg/questionable
import pkg/questionable/results

import pkg/libp2p/cid

import ./blockstore
import ../merkletree

proc putSomeProofs*(
    store: BlockStore, tree: PrometheiTree, iter: Iter[int]
): Future[?!void] {.async: (raises: [CancelledError]).} =
  let treeCid = ?tree.rootCid

  var items: seq[(Natural, Cid, PrometheiProof)]
  for i in iter:
    if i notin 0 ..< tree.leavesCount:
      return failure(
        "Invalid leaf index " & $i & ", tree with cid " & $treeCid & " has " &
          $tree.leavesCount & " leaves"
      )

    let
      blkCid = ?tree.getLeafCid(i)
      proof = ?tree.getProof(i)

    items.add((i.Natural, blkCid, proof))

  ?await store.putCidsAndProofs(treeCid, items)
  success()

proc putSomeProofs*(
    store: BlockStore, tree: PrometheiTree, iter: Iter[Natural]
): Future[?!void] {.async: (raises: [CancelledError], raw: true).} =
  store.putSomeProofs(tree, iter.map((i: Natural) => i.ord))

proc putAllProofs*(
    store: BlockStore, tree: PrometheiTree
): Future[?!void] {.async: (raises: [CancelledError], raw: true).} =
  store.putSomeProofs(tree, Iter[int].new(0 ..< tree.leavesCount))
