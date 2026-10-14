## Copyright (c) 2022 Status Research & Development GmbH

import ./erasure/erasure
import ./erasure/backends/leopard

export erasure

func leoEncoderProvider*(
    size, buffers, parity: int
): EncoderBackend {.raises: [Defect].} =
  ## create new Leo Encoder
  LeoEncoderBackend.new(size, buffers, parity)

func leoDecoderProvider*(
    size, buffers, parity: int
): DecoderBackend {.raises: [Defect].} =
  ## create new Leo Decoder
  LeoDecoderBackend.new(size, buffers, parity)
