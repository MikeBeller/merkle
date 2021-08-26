defmodule Merkle.KV do
  @moduledoc """
  An immutable key-value datastore backed by a Merkle tree
  """

  @type entry_t :: {binary, binary}
  @type hist_t :: %{optional(binary()) => [non_neg_integer()]}

  defstruct [:tree, :index, :hist]
  @type t::%__MODULE__{
    tree: Merkle.Tree.t(),
    index: %{optional(non_neg_integer()) => entry_t()},
    hist: hist_t(),
  }

  @spec update_hist(hist_t(), non_neg_integer(), entry_t()) :: hist_t()
  def update_hist(hist, ind, _entry = {k, _v}) do
    Map.update(hist, k, [ind], fn hs -> [ind | hs] end)
  end

  @spec new([entry_t()]) :: Merkle.KV.t()
  def new(entries \\ []) do
    blocks = entries
    |> Enum.map(&:erlang.term_to_binary(&1))
    index = entries
    |> Enum.with_index(fn ent,i -> {i,ent} end)
    |> Enum.into(%{})
    hist = entries
    |> Enum.with_index(fn ent,i -> {i,ent} end)
    |> Enum.reduce(%{}, fn {i,ent},hst -> update_hist(hst, i, ent) end)

    %Merkle.KV{
      tree: Merkle.Tree.new(blocks),
      index: index,
      hist: hist,
    }
  end

  @spec size(t()) :: non_neg_integer()
  def size(kv) do
    kv.tree.size
  end

  # what to do for key not present?  should I do a proof too?
  @spec get(t(), binary()) :: (entry_t() | nil)
  def get(kv, k) do
    case Map.get(kv.hist, k, nil) do
      [i | _rest] -> kv.index[i]
      nil -> nil
    end
  end

  @spec put(t(), entry_t()) :: t()
  def put(kv = %Merkle.KV{tree: tree, index: index, hist: hist}, entry) do
    ind = size(kv) + 1
    %Merkle.KV{
      tree: Merkle.Tree.add(tree, :erlang.term_to_binary(entry)),
      index: Map.put(index, ind, entry),
      hist: update_hist(hist, ind, entry),
    }
  end

  # &&& implement verified get
end
