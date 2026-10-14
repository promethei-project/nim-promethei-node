## Copyright (c) 2022 Status Research & Development GmbH

{.push raises: [].}

import ../stores

type
  ErasureBackend* = ref object of RootObj
    blockSize*: int # block size in bytes
    buffers*: int # number of original pieces
    parity*: int # number of redundancy pieces

  EncoderBackend* = ref object of ErasureBackend
  DecoderBackend* = ref object of ErasureBackend

method release*(self: ErasureBackend) {.base, gcsafe.} =
  ## release the backend
  ##
  raiseAssert("not implemented!")

method encode*(
    self: EncoderBackend, buffers, parity: var seq[seq[byte]]
): Result[void, cstring] {.base, gcsafe.} =
  ## encode buffers using a backend
  ##
  raiseAssert("not implemented!")

method decode*(
    self: DecoderBackend, buffers, parity, recovered: var seq[seq[byte]]
): Result[void, cstring] {.base, gcsafe.} =
  ## decode buffers using a backend
  ##
  raiseAssert("not implemented!")
