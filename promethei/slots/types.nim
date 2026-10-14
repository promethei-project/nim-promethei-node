type
  Sample*[SomeHash] = object
    cellData*: seq[SomeHash]
    merklePaths*: seq[SomeHash]

  PublicInputs*[SomeHash] = object
    slotIndex*: int
    datasetRoot*: SomeHash
    entropy*: SomeHash

  ProofInputs*[SomeHash] = object
    entropy*: SomeHash
    datasetRoot*: SomeHash
    slotIndex*: Natural
    slotRoot*: SomeHash
    nCellsPerSlot*: Natural
    nSlotsPerDataSet*: Natural
    slotProof*: seq[SomeHash]
      # inclusion proof that shows that the slot root (leaf) is part of the dataset (root)
    samples*: seq[Sample[SomeHash]]
      # inclusion proofs which show that the selected cells (leafs) are part of the slot (roots)
