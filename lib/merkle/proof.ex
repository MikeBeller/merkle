defmodule Merkle.Proof do
  defstruct [:id, :hashes]

  @type t :: %__MODULE__{
    id: non_neg_integer(),
    hashes: [Merkle.Tree.hash_t()],
  }
end
