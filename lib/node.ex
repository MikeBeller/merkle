defmodule Merkle.Node do
  defstruct [:hash, :children]

  @type t :: %__MODULE__ {
    hash: String.t(),
    children: [Merkle.Node.t()],
  }
end
