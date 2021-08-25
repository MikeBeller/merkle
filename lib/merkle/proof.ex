defmodule Merkle.Proof do
  defstruct [:id, :hashes]

  @type t :: %__MODULE__{
    id: non_neg_integer(),
    hashes: [Markle.hash_t()],
  }
end