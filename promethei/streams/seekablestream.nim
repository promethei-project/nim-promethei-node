## Copyright (c) 2022 Status Research & Development GmbH

import pkg/libp2p/stream/lpstream
import pkg/chronos

import ../logutils

export lpstream, chronos, logutils

logScope:
  topics = "promethei seekablestream"

type SeekableStream* = ref object of LPStream
  offset*: int

method `size`*(self: SeekableStream): int {.base.} =
  raiseAssert("method unimplemented")

proc setPos*(self: SeekableStream, pos: int) =
  self.offset = pos
