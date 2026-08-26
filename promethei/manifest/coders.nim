## Copyright (c) 2025 Promethei Authors
## Copyright (c) 2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

# This module implements serialization and deserialization of Manifest

{.push raises: [].}

import times
import std/tables
import std/sequtils

import pkg/libp2p
import pkg/questionable
import pkg/questionable/results
import pkg/chronos

import ./manifest
import ../errors
import ../blocktype
import ../logutils
import ../indexingstrategy

proc encode*(manifest: Manifest): ?!seq[byte] =
  ## Encode the manifest into a ``ManifestCodec``
  ## multicodec container (Dag-pb) for now
  ##

  ?manifest.verify()
  var pbNode = initProtoBuffer()

  # NOTE: The `Data` field in the the `dag-pb`
  # contains the following protobuf `Message`
  #
  # ```protobuf
  #   Message VerificationInfo {
  #     bytes verifyRoot = 1;             # Decimal encoded field-element
  #     repeated bytes slotRoots = 2;     # Decimal encoded field-elements
  #     optional uint32 cellSize = 3;     # Size of each slot cell
  #     optional uint32 verifiableStrategy = 4; # Indexing strategy of the slot roots
  #     optional bytes protectedTreeCid = 5;    # Root of the protected tree
  #     optional uint64 protectedDatasetSize = 6; # Physical size of the protected dataset
  #   }
  #   Message ErasureInfo {
  #     optional uint32 ecK = 1;                            # number of encoded blocks
  #     optional uint32 ecM = 2;                            # number of parity blocks
  #     optional bytes originalTreeCid = 3;                 # cid of the original dataset
  #     optional uint32 originalDatasetSize = 4;            # size of the original dataset
  #     optional VerificationInformation verification = 5;  # verification information
  #   }
  #
  #   Message Header {
  #     optional bytes treeCid = 1;       # cid (root) of the tree
  #     optional uint32 blockSize = 2;    # size of a single block
  #     optional uint64 datasetSize = 3;  # size of the dataset
  #     optional codec: MultiCodec = 4;   # Dataset codec
  #     optional hcodec: MultiCodec = 5   # Multihash codec
  #     optional version: uint32 = 6;  # manifest version
  #     optional ErasureInfo erasure = 7; # erasure coding info
  #     optional filename: ?string = 8;    # original filename
  #     optional mimetype: ?string = 9;    # original mimetype
  #     optional cidVersion: CidVersion = 10; # Cid version
  #   }
  # ```
  #
  # var treeRootVBuf = initVBuffer()
  var header = initProtoBuffer()
  header.write(1, manifest.treeCid.data.buffer)
  header.write(2, manifest.blockSize.uint32)
  header.write(3, manifest.datasetSize.uint64)
  header.write(4, manifest.codec.uint32)
  header.write(5, manifest.hcodec.uint32)
  header.write(6, manifest.version.uint32)
  header.write(10, manifest.cidVersion.uint32)

  if manifest.protected:
    var erasureInfo = initProtoBuffer()
    erasureInfo.write(1, manifest.ecK.uint32)
    erasureInfo.write(2, manifest.ecM.uint32)
    erasureInfo.write(3, manifest.originalTreeCid.data.buffer)
    erasureInfo.write(4, manifest.originalDatasetSize.uint64)
    erasureInfo.write(5, manifest.protectedStrategy.uint32)

    if manifest.verifiable:
      var verificationInfo = initProtoBuffer()
      verificationInfo.write(1, manifest.verifyRoot.data.buffer)
      for slotRoot in manifest.slotRoots:
        verificationInfo.write(2, slotRoot.data.buffer)
      verificationInfo.write(3, manifest.cellSize.uint32)
      verificationInfo.write(4, manifest.verifiableStrategy.uint32)
      verificationInfo.write(5, manifest.protectedTreeCid.data.buffer)
      verificationInfo.write(6, manifest.protectedDatasetSize.uint64)
      erasureInfo.write(6, verificationInfo)

    erasureInfo.finish()
    header.write(7, erasureInfo)

  if manifest.filename.isSome:
    header.write(8, !manifest.filename)

  if manifest.mimetype.isSome:
    header.write(9, !manifest.mimetype)

  pbNode.write(1, header) # set the treeCid as the data field
  pbNode.finish()

  return pbNode.buffer.success

proc decode*(_: type Manifest, data: openArray[byte]): ?!Manifest =
  ## Decode a manifest from a data blob
  ##

  var
    pbNode = initProtoBuffer(data)
    pbHeader: ProtoBuffer
    pbErasureInfo: ProtoBuffer
    pbVerificationInfo: ProtoBuffer
    treeCidBuf: seq[byte]
    originalTreeCid: seq[byte]
    datasetSize: uint64
    codec: uint32
    hcodec: uint32
    version: uint32
    cidVersion: uint32
    blockSize: uint32
    originalDatasetSize: uint64
    ecK, ecM: uint32
    protectedStrategy: uint32
    verifyRoot: seq[byte]
    slotRoots: seq[seq[byte]]
    cellSize: uint32
    verifiableStrategy: uint32
    protectedTreeCid: seq[byte]
    protectedDatasetSize: uint64
    filename: string
    mimetype: string

  # Decode `Header` message
  if pbNode.getField(1, pbHeader).isErr:
    return failure("Unable to decode `Header` from dag-pb manifest!")

  # Decode `Header` contents
  if pbHeader.getField(1, treeCidBuf).isErr:
    return failure("Unable to decode `treeCid` from manifest!")

  if pbHeader.getField(2, blockSize).isErr:
    return failure("Unable to decode `blockSize` from manifest!")

  if pbHeader.getField(3, datasetSize).isErr:
    return failure("Unable to decode `datasetSize` from manifest!")

  if pbHeader.getField(4, codec).isErr:
    return failure("Unable to decode `codec` from manifest!")

  if pbHeader.getField(5, hcodec).isErr:
    return failure("Unable to decode `hcodec` from manifest!")

  if pbHeader.getField(6, version).isErr:
    return failure("Unable to decode `version` from manifest!")

  if version != ManifestVersionV1:
    return failure("Unsupported manifest version")

  if pbHeader.getField(10, cidVersion).isErr:
    return failure("Unable to decode `cidVersion` from manifest!")

  if pbHeader.getField(7, pbErasureInfo).isErr:
    return failure("Unable to decode `erasureInfo` from manifest!")

  if pbHeader.getField(8, filename).isErr:
    return failure("Unable to decode `filename` from manifest!")

  if pbHeader.getField(9, mimetype).isErr:
    return failure("Unable to decode `mimetype` from manifest!")

  let protected = pbErasureInfo.buffer.len > 0
  var verifiable = false
  if protected:
    if pbErasureInfo.getField(1, ecK).isErr:
      return failure("Unable to decode `K` from manifest!")

    if pbErasureInfo.getField(2, ecM).isErr:
      return failure("Unable to decode `M` from manifest!")

    if pbErasureInfo.getField(3, originalTreeCid).isErr:
      return failure("Unable to decode `originalTreeCid` from manifest!")

    if pbErasureInfo.getField(4, originalDatasetSize).isErr:
      return failure("Unable to decode `originalDatasetSize` from manifest!")

    if pbErasureInfo.getField(5, protectedStrategy).isErr:
      return failure("Unable to decode `protectedStrategy` from manifest!")

    if pbErasureInfo.getField(6, pbVerificationInfo).isErr:
      return failure("Unable to decode `verificationInfo` from manifest!")

    verifiable = pbVerificationInfo.buffer.len > 0
    if verifiable:
      if pbVerificationInfo.getField(1, verifyRoot).isErr:
        return failure("Unable to decode `verifyRoot` from manifest!")

      if pbVerificationInfo.getRequiredRepeatedField(2, slotRoots).isErr:
        return failure("Unable to decode `slotRoots` from manifest!")

      if pbVerificationInfo.getField(3, cellSize).isErr:
        return failure("Unable to decode `cellSize` from manifest!")

      if pbVerificationInfo.getField(4, verifiableStrategy).isErr:
        return failure("Unable to decode `verifiableStrategy` from manifest!")

      if pbVerificationInfo.getField(5, protectedTreeCid).isErr:
        return failure("Unable to decode `protectedTreeCid` from manifest!")

      if pbVerificationInfo.getField(6, protectedDatasetSize).isErr:
        return failure("Unable to decode `protectedDatasetSize` from manifest!")

  let treeCid = ?Cid.init(treeCidBuf).mapFailure

  var filenameOption = if filename.len == 0: string.none else: filename.some
  var mimetypeOption = if mimetype.len == 0: string.none else: mimetype.some
  # For verifiable manifests the wire's top-level treeCid/datasetSize
  # describe the ENLARGED verifiable dataset; the protected view arrives in
  # VerificationInfo fields 5/6 and becomes the intermediate manifest's
  # treeCid/datasetSize (the verifiable ctor captures them as
  # protectedTreeCid/protectedDatasetSize).
  var
    viewTreeCidBuf = treeCidBuf
    viewDatasetSize = datasetSize
  if verifiable:
    viewTreeCidBuf = protectedTreeCid
    viewDatasetSize = protectedDatasetSize

  let self =
    if protected:
      Manifest.new(
        treeCid = ?Cid.init(viewTreeCidBuf).mapFailure,
        datasetSize = viewDatasetSize.NBytes,
        blockSize = blockSize.NBytes,
        version = version,
        cidVersion = cidVersion.CidVersion,
        hcodec = hcodec.MultiCodec,
        codec = codec.MultiCodec,
        ecK = ecK.int,
        ecM = ecM.int,
        originalTreeCid = ?Cid.init(originalTreeCid).mapFailure,
        originalDatasetSize = originalDatasetSize.NBytes,
        strategy = StrategyType(protectedStrategy),
        filename = filenameOption,
        mimetype = mimetypeOption,
      )
    else:
      Manifest.new(
        treeCid = treeCid,
        datasetSize = datasetSize.NBytes,
        blockSize = blockSize.NBytes,
        version = version,
        cidVersion = cidVersion.CidVersion,
        hcodec = hcodec.MultiCodec,
        codec = codec.MultiCodec,
        filename = filenameOption,
        mimetype = mimetypeOption,
      )

  ?self.verify()

  if verifiable:
    let
      verifyRootCid = ?Cid.init(verifyRoot).mapFailure
      slotRootCids = slotRoots.mapIt(?Cid.init(it).mapFailure)
    let final = ?Manifest.new(
      manifest = self,
      treeCid = treeCid,
      datasetSize = datasetSize.NBytes,
      verifyRoot = verifyRootCid,
      slotRoots = slotRootCids,
      cellSize = cellSize.NBytes,
      strategy = StrategyType(verifiableStrategy),
    )
    # The intermediate check above validated the protected view; the final
    # verifiable manifest carries its own geometry and must stand on its own.
    ?(final.verify())
    return success final
  self.success

func decode*(_: type Manifest, blk: Block): ?!Manifest =
  ## Decode a manifest using `decoder`
  ##

  if not ?blk.cid.isManifest:
    return failure "Cid not a manifest codec"

  Manifest.decode(blk.data)

func toBlock*(manifest: Manifest): ?!Block =
  Block.new(data = ?manifest.encode(), codec = ManifestCodec)

func toCid*(manifest: Manifest): ?!Cid =
  success (?manifest.toBlock).cid
