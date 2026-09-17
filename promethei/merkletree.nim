import ./merkletree/flatindex
import ./merkletree/merkletree
import ./merkletree/promethei
import ./merkletree/poseidon2

export promethei, flatindex, poseidon2, merkletree

type
  SomeMerkleTree* = ByteTree | PrometheiTree | Poseidon2Tree
  SomeMerkleProof* = ByteProof | PrometheiProof | Poseidon2Proof
  SomeMerkleHash* = ByteHash | Poseidon2Hash
