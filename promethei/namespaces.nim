const
  # Namespaces
  PrometheiMetaNamespace* = "meta" # meta info stored here
  PrometheiRepoNamespace* = "repo"
    # repository namespace, blocks and manifests are subkeys
  PrometheiBlockTotalNamespace* = PrometheiMetaNamespace & "/total"
    # number of blocks in the repo
  PrometheiBlocksNamespace* = PrometheiRepoNamespace & "/blocks" # blocks namespace
  PrometheiManifestNamespace* = PrometheiRepoNamespace & "/manifests"
    # manifest namespace
  PrometheiBlocksMetaNamespace* = # Block metadata namespace
    PrometheiMetaNamespace & "/blocks"
  PrometheiBlockLeafNamespace* = # Cid and Proof
    PrometheiMetaNamespace & "/leafs"
  PrometheiTreeNodeNamespace* = "tree"
  PrometheiDhtNamespace* = "dht" # Dht namespace
  PrometheiDhtProvidersNamespace* = # Dht providers namespace
    PrometheiDhtNamespace & "/providers"
  PrometheiQuotaNamespace* = PrometheiMetaNamespace & "/quota" # quota's namespace
  PrometheiOverlayNamespace* = PrometheiMetaNamespace & "/overlays"
