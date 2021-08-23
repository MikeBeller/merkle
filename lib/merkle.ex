defmodule Merkle do
  @moduledoc """
  Implementation of a Merkle tree
  """

  defstruct [:root, :blocks]

  @leaf_salt <<0>>
  @node_salt <<1>>
  @default_data ""

  def hash(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end

  def build_leaf(data) do
      %Merkle.Node{
        hash: hash(@leaf_salt <> data),
        children: [],
      }
  end

  def new do
    new([@default_data])
  end

  #def new([first]) do
  #  %Merkle{
  #    root: build_leaf(first),
  #    blocks: [first],
  #  }
  #end

  def new(blocks) when is_list(blocks) do
    ln = length(blocks)
    ht = ceil(:math.log2(ln))
    full_ln = Bitwise.bsl(1, ht)
    # pad out the blocks to length full_ln
    all_blocks = blocks ++ List.duplicate("", full_ln - ln)
    %Merkle{
      root: build_tree(full_ln, all_blocks),
      blocks: all_blocks,
    }
  end

  def build_tree(1, [data]) do
    build_leaf(data)
  end

  def build_tree(n, blocks) when rem(n, 2) == 0 do
    c = div(n, 2)
    [left, right] = Enum.chunk_every(blocks, c)
    lt = build_tree(c, left)
    rt = build_tree(c, right)
    %Merkle.Node{
      hash: hash(@node_salt <> lt.hash <> rt.hash),
      children: [lt, rt],
    }
  end
end
