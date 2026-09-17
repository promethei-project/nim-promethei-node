## Copyright (c) 2025 Promethei Authors
## Copyright (c) 2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import pkg/questionable/results
import pkg/kvstore
import pkg/libp2p
import ../namespaces
import ../manifest

{.push raises: [].}

const
  PrometheiMetaKey* = Key.init(PrometheiMetaNamespace).tryGet
  PrometheiRepoKey* = Key.init(PrometheiRepoNamespace).tryGet
  PrometheiBlocksKey* = Key.init(PrometheiBlocksNamespace).tryGet
  PrometheiTotalBlocksKey* = Key.init(PrometheiBlockTotalNamespace).tryGet
  PrometheiManifestKey* = Key.init(PrometheiManifestNamespace).tryGet
  PrometheiOverlaysKey* = Key.init(PrometheiOverlayNamespace).tryGet
  BlocksMetaKey* = Key.init(PrometheiBlocksMetaNamespace).tryGet
  BlockLeafKey* = Key.init(PrometheiBlockLeafNamespace).tryGet
  TreeNodeKey* = Key.init(PrometheiTreeNodeNamespace).tryGet
  QuotaKey* = Key.init(PrometheiQuotaNamespace).tryGet
  QuotaUsedKey* = (QuotaKey / "used").tryGet
  QuotaReservedKey* = (QuotaKey / "reserved").tryGet

func makePrefixKey*(postFixLen: int, cid: Cid): ?!Key {.inline.} =
  let cidStr = $cid
  if ?cid.isManifest:
    Key.init(
      PrometheiManifestNamespace & "/" & cidStr[^postFixLen ..^ 1] & "/" & cidStr
    )
  else:
    Key.init(PrometheiBlocksNamespace & "/" & cidStr[^postFixLen ..^ 1] & "/" & cidStr)

func overlayKey*(treeCid: Cid): ?!Key =
  ## Key for dataset overlay metadata: /meta/datasets/{treeCid}
  PrometheiOverlaysKey / $treeCid

func overlayQueryKey*(): ?!Key =
  ## Query key for iterating all datasets: /meta/datasets/*
  Key.init(?(PrometheiOverlaysKey / "*"))

func blockMetaKey*(cid: Cid): ?!Key {.inline.} =
  Key.init(PrometheiBlocksMetaNamespace & "/" & $cid)

proc blockMetaKeyQuery*(): ?!Key =
  Key.init(?(BlocksMetaKey / "*"))

func blockLeafKey*(treeCid: Cid, index: Natural): ?!Key {.inline.} =
  Key.init(PrometheiBlockLeafNamespace & "/" & $treeCid & "/" & $index)

func blockLeafKey*(treeCidStr: string, index: Natural): ?!Key {.inline.} =
  Key.init(PrometheiBlockLeafNamespace & "/" & treeCidStr & "/" & $index)

func blockLeafQueryKey*(treeCid: Cid): ?!Key =
  ## Query key for iterating all leafs under a tree: /meta/leafs/{treeCid}/*
  Key.init(?(BlockLeafKey / $treeCid / "*"))

func treeNodeKey*(treeCid: Cid, flatIdx: Natural): ?!Key {.inline.} =
  Key.init(PrometheiTreeNodeNamespace & "/" & $treeCid & "/" & $flatIdx)

func treeNodeKey*(treeCidStr: string, flatIdx: Natural): ?!Key {.inline.} =
  Key.init(PrometheiTreeNodeNamespace & "/" & treeCidStr & "/" & $flatIdx)

func treeNodeQueryKey*(treeCid: Cid): ?!Key =
  ## Query key for iterating all flat tree nodes under a tree: /tree/{treeCid}/*
  Key.init(?(TreeNodeKey / $treeCid / "*"))
