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
    quotients*: seq[SomeHash]
      # one checked quotient per sample: low192(hash) = quotient*cellCount + index
      # The circuit derives the index, so it never trusts a prover-supplied index.
