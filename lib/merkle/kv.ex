defmodule Merkle.KV do
  @moduledoc """
  An immutable key-value datastore backed by a Merkle tree
  """

  defstruct [:tree, :index]
  @type t::%__MODULE__{
    tree: Merkle.Tree.t(),
    index: %{optional(binary()) => non_neg_integer()},
  }
end
