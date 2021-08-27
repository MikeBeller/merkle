defmodule Merkle.IProof do
  defstruct [:i, :j, :hashes]

  @type t :: %__MODULE__{
    i: non_neg_integer(),
    j: non_neg_integer(),
    hashes: [Merkle.Tree.hash_t()],
  }
end
