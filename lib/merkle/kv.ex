defmodule Merkle.KV do
  @moduledoc """
  An immutable key-value datastore backed by a Merkle tree
  """

  @type entry_t :: {binary, binary}

  defstruct [:tree, :index, :hist]
  @type t::%__MODULE__{
    tree: Merkle.Tree.t(),
    index: %{optional(non_neg_integer()) => entry_t()},
    hist: %{optional(binary()) => [non_neg_integer()]},
  }
end
