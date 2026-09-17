## Copyright (c) 2025 Promethei Authors
## Copyright (c) 2023 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

{.push raises: [].}

import std/bitops
import std/sequtils

import pkg/questionable
import pkg/questionable/results
import pkg/libp2p/[cid, multicodec, multihash]
import pkg/constantine/hashes
import ../../utils
import ../../rng
import ../../errors
import ../../blocktype

from ../../utils/digest import digestBytes

import ../merkletree

export merkletree

logScope:
  topics = "promethei merkletree"

type
  ByteTreeKey* {.pure.} = enum
    KeyNone = 0x0.byte
    KeyBottomLayer = 0x1.byte
    KeyOdd = 0x2.byte
    KeyOddAndBottomLayer = 0x3.byte

  ByteHash* = seq[byte]
  ByteTree* = MerkleTree[ByteHash, ByteTreeKey]
  ByteProof* = MerkleProof[ByteHash, ByteTreeKey]

  PrometheiTree* = ref object of ByteTree
    mcodec*: MultiCodec

  PrometheiProof* = object of ByteProof
    mcodec*: MultiCodec

func getProof*(self: PrometheiTree, index: int): ?!PrometheiProof =
  var proof = PrometheiProof(mcodec: self.mcodec)

  ?self.getProof(index, proof)

  success proof

func verify*(self: PrometheiProof, leaf: MultiHash, root: MultiHash): ?!bool =
  ## Verify hash
  ##

  let
    rootBytes = root.digestBytes
    leafBytes = leaf.digestBytes

  if self.mcodec != root.mcodec or self.mcodec != leaf.mcodec:
    return failure "Hash codec mismatch"

  if rootBytes.len != root.size and leafBytes.len != leaf.size:
    return failure "Invalid hash length"

  self.verify(leafBytes, rootBytes)

func verify*(self: PrometheiProof, leaf: Cid, root: Cid): ?!bool =
  self.verify(?leaf.mhash.mapFailure, ?root.mhash.mapFailure)

proc rootCid*(
    self: PrometheiTree, version = CIDv1, dataCodec = DatasetRootCodec
): ?!Cid =
  if (?self.root).len == 0:
    return failure "Empty root"

  let mhash = ?MultiHash.init(self.mcodec, ?self.root).mapFailure

  Cid.init(version, DatasetRootCodec, mhash).mapFailure

func getLeafCid*(
    self: PrometheiTree, i: Natural, version = CIDv1, dataCodec = BlockCodec
): ?!Cid =
  if i >= self.leavesCount:
    return failure "Invalid leaf index " & $i

  let
    leaf = self.leaves[i]
    mhash = ?MultiHash.init($self.mcodec, leaf).mapFailure

  Cid.init(version, dataCodec, mhash).mapFailure

proc `$`*(self: PrometheiTree): string =
  let root =
    if self.root.isOk:
      byteutils.toHex(self.root.get)
    else:
      "none"
  "PrometheiTree(" & " root: " & root & ", leavesCount: " & $self.leavesCount &
    ", levels: " & $self.levels & ", mcodec: " & $self.mcodec & " )"

proc `$`*(self: PrometheiProof): string =
  "PrometheiProof(" & " nleaves: " & $self.nleaves & ", index: " & $self.index &
    ", path: " & $self.path.mapIt(byteutils.toHex(it)) & ", mcodec: " & $self.mcodec &
    " )"

func compress*(x, y: openArray[byte], key: ByteTreeKey): ?!ByteHash =
  ## Compress two hashes
  ##

  # Using Constantine's SHA256 instead of mhash for optimal performance on 32-byte merkle node hashing
  # See: https://github.com/logos-storage/nim-codex/issues/1162

  let input = @x & @y & @[key.byte]
  var digest = hashes.sha256.hash(input)

  success @digest

func init*(
    _: type PrometheiTree,
    mcodec: MultiCodec = Sha256HashCodec,
    leaves: openArray[ByteHash],
): ?!PrometheiTree =
  if leaves.len == 0:
    return failure "Empty leaves"

  let
    digestSize = ?mcodec.digestSize.mapFailure
    compressor = proc(x, y: seq[byte], key: ByteTreeKey): ?!ByteHash {.noSideEffect.} =
      compress(x, y, key)
    Zero: ByteHash = newSeq[byte](digestSize)

  if digestSize != leaves[0].len:
    return failure "Invalid hash length"

  var self = PrometheiTree(mcodec: mcodec, compress: compressor, zero: Zero)

  self.layers = ?merkleTreeWorker(self, leaves, isBottomLayer = true)
  success self

func init*(_: type PrometheiTree, leaves: openArray[MultiHash]): ?!PrometheiTree =
  if leaves.len == 0:
    return failure "Empty leaves"

  let
    mcodec = leaves[0].mcodec
    leaves = leaves.mapIt(it.digestBytes)

  PrometheiTree.init(mcodec, leaves)

func init*(_: type PrometheiTree, leaves: openArray[Cid]): ?!PrometheiTree =
  if leaves.len == 0:
    return failure "Empty leaves"

  let
    mcodec = (?leaves[0].mhash.mapFailure).mcodec
    leaves = leaves.mapIt((?it.mhash.mapFailure).digestBytes)

  PrometheiTree.init(mcodec, leaves)

proc fromNodes*(
    _: type PrometheiTree,
    mcodec: MultiCodec = Sha256HashCodec,
    nodes: openArray[ByteHash],
    nleaves: int,
): ?!PrometheiTree =
  if nodes.len == 0:
    return failure "Empty nodes"

  let
    digestSize = ?mcodec.digestSize.mapFailure
    Zero = newSeq[byte](digestSize)
    compressor = proc(x, y: seq[byte], key: ByteTreeKey): ?!ByteHash {.noSideEffect.} =
      compress(x, y, key)

  if digestSize != nodes[0].len:
    return failure "Invalid hash length"

  var
    self = PrometheiTree(compress: compressor, zero: Zero, mcodec: mcodec)
    layer = nleaves
    pos = 0

  while pos < nodes.len:
    self.layers.add(nodes[pos ..< (pos + layer)])
    pos += layer
    layer = divUp(layer, 2)

  let
    index = Rng.instance.rand(nleaves - 1)
    proof = ?self.getProof(index)

  if not ?proof.verify(self.leaves[index], ?self.root): # sanity check
    return failure "Unable to verify tree built from nodes"

  success self

func init*(
    _: type PrometheiProof,
    mcodec: MultiCodec = Sha256HashCodec,
    index: int,
    nleaves: int,
    nodes: openArray[ByteHash],
): ?!PrometheiProof =
  if nodes.len == 0:
    return failure "Empty nodes"

  let
    digestSize = ?mcodec.digestSize.mapFailure
    Zero = newSeq[byte](digestSize)
    compressor = proc(x, y: seq[byte], key: ByteTreeKey): ?!seq[byte] {.noSideEffect.} =
      compress(x, y, key)

  success PrometheiProof(
    compress: compressor,
    zero: Zero,
    mcodec: mcodec,
    index: index,
    nleaves: nleaves,
    path: @nodes,
  )
