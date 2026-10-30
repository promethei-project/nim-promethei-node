import std/[os, osproc, times]

import pkg/chronos
import pkg/chronos/transports/common
import pkg/chronos/transports/stream
import pkg/chronos/apps/http/httpcommon
import pkg/chronos/apps/http/httpserver
import pkg/ethers
import pkg/questionable/results
import pkg/zippy/tarballs
import pkg/promethei/marketplace/contracts/marketplacecontract
import pkg/promethei/marketplace/contracts/deployment
import ../../asynctest
import ../../testbed

const
  cirdl = "build" / "tools" / "cirdl" / "cirdl"
  workdir = "."
  storageEnv = "PROMETHEI_CIRCUIT_STORAGE_URL"
  PollIntervalMillis = 50
  ChildTimeoutPolls = 1200 ## ~60s for the downloader to finish
  ChildReapTimeoutMs = 2000
  archiveMembers = [
    "proof_main.r1cs", "proof_main.wasm", "proof_main.zkey",
    "proof_main_verification_key.json",
  ]

var
  servePath {.threadvar.}: string
  serveBody {.threadvar.}: seq[byte]
  requestedPaths {.threadvar.}: seq[string]

proc toBytes(data: string): seq[byte] =
  result = newSeq[byte](data.len)
  if data.len > 0:
    copyMem(result[0].addr, data[0].unsafeAddr, data.len)

proc buildArchive(): seq[byte] =
  ## The archive is synthetic on purpose: this test covers downloading and
  ## extracting whatever the chain points at, not the circuit itself. Entries
  ## live at the archive root, like the published archives.
  let
    tarball = Tarball()
    archive = getTempDir() / "cirdl-archive.tar.gz"

  for name in archiveMembers:
    tarball.contents[name] = TarballEntry(
      kind: ekNormalFile,
      contents: "test " & name,
      lastModified: fromUnix(0),
      permissions: {fpUserRead, fpUserWrite, fpGroupRead, fpOthersRead},
    )

  removeFile(archive)
  tarball.writeTarball(archive)
  result = toBytes(readFile(archive))
  removeFile(archive)

proc processCallback(
    req: RequestFence
): Future[HttpResponseRef] {.async: (raises: [CancelledError]).} =
  if req.isErr:
    raiseAssert("malformed http request")
  let request = req.get()
  requestedPaths.add(request.uri.path)
  try:
    if request.uri.path == servePath:
      await request.respond(Http200, serveBody)
    else:
      await request.respond(Http404, "not found")
  except HttpWriteError as exc:
    raiseAssert("failed to write response: " & exc.msg)

suite "tools/cirdl":
  var testbed: Testbed
  var hardhat: Hardhat

  setup:
    testbed = await Testbed.start()
    hardhat = await testbed.hardhat.start()

  teardown:
    await testbed.stop()

  test "circuit download tool":
    let circuitPath = "testcircuitpath"
    discard existsOrCreateDir(circuitPath)

    let
      provider = await JsonRpcProvider.connect(hardhat.jsonRpcUrl)
      marketplaceAddress = (await provider.getMarketplaceAddress()).tryGet()
      marketplace = MarketplaceContract.new(marketplaceAddress, provider)
      configuration = await marketplace.configuration()

    # Serve the archive at the path the deployment advertises, so a client
    # that used any other hash would not find it.
    servePath = "/" & configuration.proofs.zkeyHash
    serveBody = buildArchive()
    requestedPaths = @[]

    let server =
      HttpServerRef.new(initTAddress("127.0.0.1:0"), processCallback).tryGet()
    server.start()
    let port = server.instance.localAddress().port

    let
      hadOverride = existsEnv(storageEnv)
      priorOverride = getEnv(storageEnv)

    var
      process: Process
      timedOut = false
      returnCode = -1

    putEnv(storageEnv, "http://127.0.0.1:" & $port)

    try:
      process = startProcess(
        cirdl,
        workdir,
        args = @[circuitPath, hardhat.jsonRpcUrl],
        options = {poParentStreams},
      )

      # waitForExit would block the event loop serving the archive
      var waited = 0
      while running(process):
        if waited >= ChildTimeoutPolls:
          timedOut = true
          terminate(process)
          discard waitForExit(process, ChildReapTimeoutMs)
          if running(process):
            kill(process)
            discard waitForExit(process, ChildReapTimeoutMs)
          break
        inc waited
        await sleepAsync(PollIntervalMillis.millis)

      if not timedOut:
        returnCode = peekExitCode(process)
    finally:
      if process != nil:
        close(process)
      await server.stop()
      if hadOverride:
        putEnv(storageEnv, priorOverride)
      else:
        delEnv(storageEnv)

    check not timedOut
    check returnCode == 0
    check servePath in requestedPaths

    for name in archiveMembers:
      check fileExists(circuitPath / name)

    removeDir(circuitPath)
