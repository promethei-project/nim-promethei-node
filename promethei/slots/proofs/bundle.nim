{.push raises: [].}

import std/json

import pkg/questionable/results

type ProofBundleMeta* = object
  innerK*: int
  innerN*: int
  maxSlotDepth*: int
  maxDatasetDepth*: int
  maxBlockDepth*: int
  maxCellElms*: int
  numSamples*: int
  allowedCounts*: seq[int]

proc load*(_: type ProofBundleMeta, path: string): ?!ProofBundleMeta =
  try:
    let node = parseFile(path)
    var counts: seq[int]
    for value in node["allowedCounts"].items:
      counts.add value.getInt

    success ProofBundleMeta(
      innerK: node["innerK"].getInt,
      innerN: node["innerN"].getInt,
      maxSlotDepth: node["maxSlotDepth"].getInt,
      maxDatasetDepth: node["maxDatasetDepth"].getInt,
      maxBlockDepth: node["maxBlockDepth"].getInt,
      maxCellElms: node["maxCellElms"].getInt,
      numSamples: node["numSamples"].getInt,
      allowedCounts: counts,
    )
  except CatchableError as exc:
    failure("Unable to read proof bundle metadata: " & exc.msg)

func expectedAllowedCounts*(meta: ProofBundleMeta): ?!seq[int] =
  ## The circuit pins one legal cell count per slot-tree height. Recompute
  ## the table from the authenticated rate instead of trusting the metadata.
  let
    k = meta.innerK
    n = meta.innerN
    maxDepth = meta.maxSlotDepth

  if k <= 0 or n <= k or n > 65536 or meta.maxBlockDepth < 0 or meta.maxBlockDepth > 30 or
      maxDepth < 0 or maxDepth > 32:
    return failure("Proof bundle metadata has invalid rate or depth")

  let cellsPerBlock = 1 shl meta.maxBlockDepth
  var
    counts = newSeq[int](maxDepth + 1)
    limit = 1 shl maxDepth
    t = 1

  while t < k:
    t = t * 2

  while t <= limit:
    let
      cells = cellsPerBlock * ((t * n * n + k * k - 1) div (k * k))
      height = block:
        var
          h = 0
          width = 1
        while width < cells:
          width = width * 2
          inc h
        h

    if height > maxDepth:
      break
    if counts[height] != 0 and counts[height] != cells:
      return failure("Proof bundle metadata has a non-unique cell-count table")
    counts[height] = cells
    t = t * 2

  success counts
