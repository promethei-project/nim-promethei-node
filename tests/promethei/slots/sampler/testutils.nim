import std/options
import std/sugar

import ../../../asynctest

import pkg/questionable/results
import pkg/constantine/math/arithmetic
import pkg/constantine/math/io/io_bigints
import pkg/constantine/math/io/io_fields
import pkg/poseidon2/io
import pkg/poseidon2
import pkg/chronos
import pkg/promethei/chunker
import pkg/promethei/stores
import pkg/promethei/blocktype as bt
import pkg/promethei/marketplace/contracts/requests
import pkg/promethei/marketplace/contracts
import pkg/promethei/merkletree
import pkg/promethei/slots/types
import pkg/promethei/slots/sampler/utils
import pkg/promethei/utils/json

import ../backends/helpers
import ../../helpers
import ../../examples
import ../../merkletree/helpers

suite "Test proof sampler utils":
  let cellsPerBlock = DefaultBlockSize div DefaultCellSize

  var
    inputData: string
    inputJson: JsonNode
    proofInput: ProofInputs[Poseidon2Hash]

  setup:
    inputData = readFile("tests/circuits/fixtures/input.json")
    inputJson = !JsonNode.parse(inputData)
    proofInput = Poseidon2Hash.jsonToProofInput(inputJson)

  proc getExpectedIndex(i: int, nCells: int): Natural =
    let hash =
      Sponge.digest(@[proofInput.entropy, proofInput.slotRoot, toF(i)], rate = 2)
    let elm: BigInt[254] = hash.toBig()

    var limbs: array[6, uint32]
    for limb in 0 ..< 6:
      for b in 0 ..< 32:
        if uint64(bit[254](elm, limb * 32 + b)) != 0:
          limbs[limb] = limbs[limb] or (1'u32 shl b)

    var remainder = 0'u64
    for limb in countdown(5, 0):
      let current = (remainder shl 32) or limbs[limb].uint64
      remainder = current mod nCells.uint64

    Natural(remainder)

  proc getExpectedQuotient(i: int, nCells: int): Poseidon2Hash =
    let hash =
      Sponge.digest(@[proofInput.entropy, proofInput.slotRoot, toF(i)], rate = 2)
    let elm: BigInt[254] = hash.toBig()

    var
      limbs: array[6, uint32]
      quotientLimbs: array[6, uint32]
      remainder = 0'u64

    for limb in 0 ..< 6:
      for b in 0 ..< 32:
        if uint64(bit[254](elm, limb * 32 + b)) != 0:
          limbs[limb] = limbs[limb] or (1'u32 shl b)

    for limb in countdown(5, 0):
      let current = (remainder shl 32) or limbs[limb].uint64
      quotientLimbs[limb] = uint32(current div nCells.uint64)
      remainder = current mod nCells.uint64

    var bytes: array[32, byte]
    for limb in 0 ..< 6:
      bytes[limb * 4 + 0] = byte(quotientLimbs[limb] and 0xff)
      bytes[limb * 4 + 1] = byte((quotientLimbs[limb] shr 8) and 0xff)
      bytes[limb * 4 + 2] = byte((quotientLimbs[limb] shr 16) and 0xff)
      bytes[limb * 4 + 3] = byte((quotientLimbs[limb] shr 24) and 0xff)

    Poseidon2Hash.fromBytes(bytes).get

  test "Can derive the quotient for non-power-of-two counts":
    for nCells in [5, 7, 11, 14, 1000]:
      for i in 1 .. 5:
        let (index, quotient) = cellIndexAndQuotient(
          proofInput.entropy, proofInput.slotRoot, nCells.Natural, i.Natural
        )
        check:
          index == getExpectedIndex(i, nCells)
          quotient == getExpectedQuotient(i, nCells)

  test "Extract low bits":
    proc extract(value: uint64, nBits: int): uint64 =
      let big = toF(value).toBig()
      return extractLowBits(big, nBits)

    check:
      extract(0x88, 4) == 0x8.uint64
      extract(0x88, 7) == 0x8.uint64
      extract(0x9A, 5) == 0x1A.uint64
      extract(0x9A, 7) == 0x1A.uint64
      extract(0x1248, 10) == 0x248.uint64
      extract(0x1248, 12) == 0x248.uint64
      extract(0x1248306A560C9AC0.uint64, 10) == 0x2C0.uint64
      extract(0x1248306A560C9AC0.uint64, 12) == 0xAC0.uint64
      extract(0x1248306A560C9AC0.uint64, 50) == 0x306A560C9AC0.uint64
      extract(0x1248306A560C9AC0.uint64, 52) == 0x8306A560C9AC0.uint64

  test "Can find single slot-cell index":
    proc slotCellIndex(i: Natural): Natural =
      return
        cellIndex(proofInput.entropy, proofInput.slotRoot, proofInput.nCellsPerSlot, i)

    check:
      slotCellIndex(1) == getExpectedIndex(1, proofInput.nCellsPerSlot.int)
      slotCellIndex(2) == getExpectedIndex(2, proofInput.nCellsPerSlot.int)
      slotCellIndex(3) == getExpectedIndex(3, proofInput.nCellsPerSlot.int)

  test "Can reduce a non-power-of-two cell count":
    let nCells = 1000
    for i in 1 .. 5:
      let index =
        cellIndex(proofInput.entropy, proofInput.slotRoot, nCells.Natural, i.Natural)
      check:
        index == getExpectedIndex(i, nCells)
        index.int < nCells

  test "Can find sequence of slot-cell indices":
    proc slotCellIndices(n: int): seq[Natural] =
      cellIndices(
        proofInput.entropy, proofInput.slotRoot, numCells = proofInput.nCellsPerSlot, n
      )

    proc getExpectedIndices(n: int): seq[Natural] =
      return collect(
        newSeq,
        (;
          for i in 1 .. n:
            cellIndex(
              proofInput.entropy, proofInput.slotRoot, proofInput.nCellsPerSlot, i
            )
        ),
      )

    check:
      slotCellIndices(3) == getExpectedIndices(3)

  for (input, expected) in [(10, 0), (255, 0), (256, 1), (511, 1), (512, 2)]:
    test "Can get slotBlockIndex from slotCellIndex (" & $input & " -> " & $expected &
      ")":
      let slotBlockIndex = toBlkInSlot(input, numCells = cellsPerBlock)

      check:
        slotBlockIndex == expected

  for (input, expected) in [(10, 10), (255, 255), (256, 0), (511, 255), (512, 0)]:
    test "Can get blockCellIndex from slotCellIndex (" & $input & " -> " & $expected &
      ")":
      let blockCellIndex = toCellInBlk(input, numCells = cellsPerBlock)

      check:
        blockCellIndex == expected
