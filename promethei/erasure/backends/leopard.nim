import std/options
import std/locks

import pkg/leopard
import pkg/results

import ../backend

# LeoCoder.init performs the leopard library's first-use initialization
# (table setup) via a thread-local `once`; a second thread reaching
# leo_encode before that init completes sees Leopard_CallInitialize.
# Serialize first-use coder construction process-wide.
var leoCoderInitLock: Lock
leoCoderInitLock.initLock()

type
  LeoEncoderBackend* = ref object of EncoderBackend
    encoder*: Option[LeoEncoder]

  LeoDecoderBackend* = ref object of DecoderBackend
    decoder*: Option[LeoDecoder]

method encode*(
    self: LeoEncoderBackend, data, parity: var seq[seq[byte]]
): Result[void, cstring] =
  ## Encode data using Leopard backend

  if parity.len == 0:
    return ok()

  # Leopard copies bufSize bytes per shard regardless of the buffer's real
  # length; short or over-long shards would read out of bounds.
  for shard in data:
    if shard.len != self.blockSize.int:
      return Result[void, cstring].err(
        "Encode shard length does not match block size"
      )
  for shard in parity:
    if shard.len != self.blockSize.int:
      return Result[void, cstring].err(
        "Parity work buffer length does not match block size"
      )

  var encoder =
    if self.encoder.isNone:
      withLock leoCoderInitLock:
        self.encoder =
          (?LeoEncoder.init(self.blockSize, self.buffers, self.parity)).some
      self.encoder.get()
    else:
      self.encoder.get()

  encoder.encode(data, parity)

method decode*(
    self: LeoDecoderBackend, data, parity, recovered: var seq[seq[byte]]
): Result[void, cstring] =
  ## Decode data using given Leopard backend

  # The wrapper copies bufSize bytes for any NON-EMPTY shard and treats
  # empty shards as missing (nil pointer). A present shard must be exactly
  # blockSize or it would read out of bounds; empty is the erasure marker.
  for shard in data:
    if shard.len > 0 and shard.len != self.blockSize.int:
      return Result[void, cstring].err(
        "Decode shard length does not match block size"
      )
  for shard in parity:
    if shard.len > 0 and shard.len != self.blockSize.int:
      return Result[void, cstring].err(
        "Parity shard length does not match block size"
      )

  var decoder =
    if self.decoder.isNone:
      withLock leoCoderInitLock:
        self.decoder =
          (?LeoDecoder.init(self.blockSize, self.buffers, self.parity)).some
      self.decoder.get()
    else:
      self.decoder.get()

  decoder.decode(data, parity, recovered)

method release*(self: LeoEncoderBackend) =
  if self.encoder.isSome:
    self.encoder.get().free()

method release*(self: LeoDecoderBackend) =
  if self.decoder.isSome:
    self.decoder.get().free()

proc new*(
    T: type LeoEncoderBackend, blockSize, buffers, parity: int
): LeoEncoderBackend =
  ## Create an instance of an Leopard Encoder backend
  ##
  LeoEncoderBackend(blockSize: blockSize, buffers: buffers, parity: parity)

proc new*(
    T: type LeoDecoderBackend, blockSize, buffers, parity: int
): LeoDecoderBackend =
  ## Create an instance of an Leopard Decoder backend
  ##
  LeoDecoderBackend(blockSize: blockSize, buffers: buffers, parity: parity)
