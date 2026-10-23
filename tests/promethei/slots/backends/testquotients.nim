import std/options
import std/os

import ../../../asynctest

import pkg/chronos
import pkg/poseidon2
import pkg/poseidon2/io
import pkg/questionable/results
import pkg/serde/json

import pkg/promethei/slots {.all.}

import ./helpers

func increment(hash: Poseidon2Hash): Poseidon2Hash =
  var
    bytes = hash.toBytes
    carry = 1'u16
  for i in 0 ..< bytes.len:
    let value = uint16(bytes[i]) + carry
    bytes[i] = byte(value and 0xff)
    carry = value shr 8
    if carry == 0:
      break
  Poseidon2Hash.fromBytes(bytes).get

suite "Quotient constraints":
  let
    r1cs = "tests/circuits/quotient/proof_main.r1cs"
    wasm = "tests/circuits/quotient/proof_main.wasm"
    zkey = "tests/circuits/quotient/proof_main.zkey"

  var
    backend: CircomCompatBackendRef
    proofInputs: ProofInputs[Poseidon2Hash]

  setup:
    let inputJson = !JsonNode.parse(readFile("tests/circuits/quotient/input.json"))
    proofInputs = Poseidon2Hash.jsonToProofInput(inputJson)
    backend = CircomCompatBackendRef
      .new(
        r1cs,
        wasm,
        zkey,
        slotDepth = 8,
        datasetDepth = 2,
        blkDepth = 1,
        cellElms = 2,
        numSamples = 2,
      )
      .tryGet()

  teardown:
    backend.release()

  test "Accepts a valid non-power-of-two population":
    let proof = (await backend.prove(proofInputs)).tryGet
    check (await backend.verify(proof, proofInputs)).tryGet

  test "Rejects an altered quotient":
    proofInputs.quotients[0] = increment(proofInputs.quotients[0])

    let proof = await backend.prove(proofInputs)
    if proof.isOk:
      check (await backend.verify(proof.get, proofInputs)).tryGet == false
    else:
      check proof.isErr

  test "Rejects a valid tree with a count outside the allowed table":
    let inputJson =
      !JsonNode.parse(readFile("tests/circuits/quotient/input_illegal.json"))
    let illegalInputs = Poseidon2Hash.jsonToProofInput(inputJson)

    let proof = await backend.prove(illegalInputs)
    if proof.isOk:
      check (await backend.verify(proof.get, illegalInputs)).tryGet == false
    else:
      check proof.isErr
