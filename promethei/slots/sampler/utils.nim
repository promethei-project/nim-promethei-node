import std/bitops
import std/options

import pkg/questionable/results
import pkg/constantine/math/arithmetic
import pkg/poseidon2/io

import ../../merkletree

func extractLowBits*[n: static int](elm: BigInt[n], k: int): uint64 =
  doAssert(k > 0 and k <= 64)
  var r = 0'u64
  for i in 0 ..< k:
    let b = bit[n](elm, i)
    let y = uint64(b)
    if (y != 0):
      r = bitor(r, 1'u64 shl i)
  r

func extractLowBits(fld: Poseidon2Hash, k: int): uint64 =
  let elm: BigInt[254] = fld.toBig()
  return extractLowBits(elm, k)

func floorLog2*(x: int): int =
  doAssert (x > 0)
  var k = -1
  var y = x
  while (y > 0):
    k += 1
    y = y shr 1
  return k

func ceilingLog2*(x: int): int =
  doAssert (x > 0)
  if x == 1:
    return 0
  return (floorLog2(x - 1) + 1)

func toBlkInSlot*(cell: Natural, numCells: Natural): Natural {.gcsafe.} =
  let log2 = ceilingLog2(numCells)
  doAssert(1 shl log2 == numCells, "`numCells` is assumed to be a power of two")

  return cell div numCells

func toCellInBlk*(cell: Natural, numCells: Natural): Natural =
  let log2 = ceilingLog2(numCells)
  doAssert(1 shl log2 == numCells, "`numCells` is assumed to be a power of two")

  return cell mod numCells

func low192Limbs(fld: Poseidon2Hash): array[6, uint32] =
  ## The challenge is reduced modulo any slot-cell count, not masked to the
  ## next power of two. Six 32-bit limbs keep that arithmetic exact and simple.
  let elm: BigInt[254] = fld.toBig()
  for limb in 0 ..< 6:
    var v = 0'u32
    for i in 0 ..< 32:
      if uint64(bit[254](elm, limb * 32 + i)) != 0:
        v = v or (1'u32 shl i)
    result[limb] = v

func divModLow192(
    limbs: array[6, uint32], divisor: uint64
): (array[6, uint32], uint64) =
  doAssert divisor > 0 and divisor <= (1'u64 shl 32)
  var
    quotient: array[6, uint32]
    remainder = 0'u64
  for i in countdown(5, 0):
    let current = (remainder shl 32) or limbs[i].uint64
    quotient[i] = uint32(current div divisor)
    remainder = current mod divisor
  (quotient, remainder)

func hashFromLimbs(limbs: array[6, uint32]): Poseidon2Hash =
  var bytes: array[32, byte]
  for i in 0 ..< 6:
    bytes[i * 4 + 0] = byte(limbs[i] and 0xff)
    bytes[i * 4 + 1] = byte((limbs[i] shr 8) and 0xff)
    bytes[i * 4 + 2] = byte((limbs[i] shr 16) and 0xff)
    bytes[i * 4 + 3] = byte((limbs[i] shr 24) and 0xff)
  Poseidon2Hash.fromBytes(bytes).get

func cellIndexAndQuotient*(
    entropy: Poseidon2Hash, slotRoot: Poseidon2Hash, numCells: Natural, counter: Natural
): (Natural, Poseidon2Hash) =
  doAssert numCells > 0

  let hash = Sponge.digest(@[entropy, slotRoot, counter.toF], rate = 2)
  let (quotient, index) = divModLow192(low192Limbs(hash), numCells.uint64)
  (Natural(index), hashFromLimbs(quotient))

func cellIndex*(
    entropy: Poseidon2Hash, slotRoot: Poseidon2Hash, numCells: Natural, counter: Natural
): Natural =
  int(cellIndexAndQuotient(entropy, slotRoot, numCells, counter)[0])

func cellIndices*(
    entropy: Poseidon2Hash,
    slotRoot: Poseidon2Hash,
    numCells: Natural,
    nSamples: Natural,
): seq[Natural] =
  var indices: seq[Natural]
  for i in 1 .. nSamples:
    indices.add(cellIndex(entropy, slotRoot, numCells, i))

  indices

func cellIndicesAndQuotients*(
    entropy: Poseidon2Hash,
    slotRoot: Poseidon2Hash,
    numCells: Natural,
    nSamples: Natural,
): (seq[Natural], seq[Poseidon2Hash]) =
  var
    indices: seq[Natural]
    quotients: seq[Poseidon2Hash]

  for i in 1 .. nSamples:
    let (index, quotient) = cellIndexAndQuotient(entropy, slotRoot, numCells, i)
    indices.add index
    quotients.add quotient

  (indices, quotients)
