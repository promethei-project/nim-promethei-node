## One-off fixture regenerator (run from the repository root): rebuilds
## tests/circuits/fixtures/input.json
## for the current cell layout (64 cells per block). The circuit artifacts
## (r1cs/wasm/zkey) are compiled separately; this tool only regenerates the
## witness input.

import std/[os, strutils]

import pkg/questionable/results
import pkg/chronos
import pkg/kvstore
import pkg/taskpools

import pkg/promethei/stores
import pkg/promethei/prometheitypes
import pkg/promethei/merkletree
import pkg/promethei/chunker
import pkg/promethei/blocktype as bt
import pkg/promethei/conf
import pkg/promethei/manifest
import pkg/promethei/utils/poseidon2digest
import pkg/promethei/slots
import pkg/promethei/slots/builder
import pkg/poseidon2/io

import ../../tests/promethei/slots/backends/helpers
import ../../tests/promethei/slots/helpers
import ../../tests/promethei/helpers

proc main() {.async.} =
  let
    samples = 5
    blockSize = DefaultBlockSize
    cellSize = DefaultCellSize
    challenge = 1234567.toF.toBytes.toArray32

  var
    dbTp = Taskpool.new(num_threads = 4)
    repoDs = SQLiteKVStore.new(SqliteMemory, dbTp).tryGet()
    metaDs = SQLiteKVStore.new(SqliteMemory, dbTp).tryGet()

  let store = RepoStore.new(repoDs, metaDs)

  let (_, _, verifiable) = await createVerifiableManifest(
    store,
    8, # number of blocks in the original dataset (before EC)
    5, # ecK
    3, # ecM
    blockSize,
    cellSize,
    dbTp,
  )

  let
    builder = Poseidon2Builder.new(
      store, store, verifiable, verifiable.verifiableStrategy
    ).tryGet
    sampler = Poseidon2Sampler.new(1, store, builder).tryGet
    proofInput = (await sampler.getProofInput(challenge, samples)).tryGet

  writeFile("tests/circuits/fixtures/input.json", $proofInput.toJson)

  echo "Fixture regenerated: input.json"
  await store.close()
  dbTp.shutdown()

waitFor main()
