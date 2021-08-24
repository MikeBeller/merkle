defmodule Merkle do
  use Bitwise

  @moduledoc """
  Implementation of a Merkle tree
  """

  defstruct [:root, :blocks, :height]
  @type t :: %__MODULE__ {
    root: Merkle.Node.t(),
    blocks: [binary],
    height: non_neg_integer(),
  }

  @leaf_salt <<0>>
  @node_salt <<1>>
  @default_data ""

  @spec hash(binary)::binary
  def hash(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end

  defp build_leaf(data) do
      %Merkle.Node{
        hash: hash(@leaf_salt <> data),
        children: [],
      }
  end

  @spec new() :: Merkle.t()
  def new do
    new([@default_data])
  end

  @spec new(list) :: Merkle.t()
  def new(blocks) when is_list(blocks) do
    ln = length(blocks)
    ht = ceil(:math.log2(ln))
    full_ln = 1 <<< ht
    # pad out the blocks to length full_ln
    all_blocks = blocks ++ List.duplicate("", full_ln - ln)
    %Merkle{
      root: build_tree(full_ln, all_blocks),
      blocks: all_blocks,
      height: ht,
    }
  end

  defp build_tree(1, [data]) do
    build_leaf(data)
  end

  defp build_tree(n, blocks) when rem(n, 2) == 0 do
    c = div(n, 2)
    [left, right] = Enum.chunk_every(blocks, c)
    lt = build_tree(c, left)
    rt = build_tree(c, right)
    %Merkle.Node{
      hash: hash(@node_salt <> lt.hash <> rt.hash),
      children: [lt, rt],
    }
  end

  @spec path(non_neg_integer | Merkle.t(), integer) :: [non_neg_integer()]
  def path(%Merkle{height: ht}, i) when i < (1 <<< ht), do: path(ht, i)
  def path(ht, i) when is_integer(ht) do
    p = Integer.digits(i, 2)
    List.duplicate(0, ht-length(p)) ++ p
  end

  def proof(t = %Merkle{root: root}, ind) do
    pth = path(t, ind)
    proof(root, pth, [root.hash])
  end

  @spec proof(Merkle.Node.t(), [non_neg_integer()], [binary]) :: [binary]
  def proof(%Merkle.Node{}, [], pf), do: pf
  def proof(%Merkle.Node{children: children}, [p | path], pf) do
    [l, r] = children
    case p do
      0 -> proof(l, path, [r.hash | pf])
      1 -> proof(r, path, [l.hash | pf])
    end
  end

  @spec proven?(binary, non_neg_integer(), [binary]) :: boolean
  @doc """
  Verifies that proof pf is a valid proof for block_data at index ind
  Index is only needed so you can hash the successive items in the correct order
  """
  def proven?(block_data, ind, pf) when is_integer(ind) do
    ht = length(pf) - 1
    pth = path(ht, ind) |> Enum.reverse()
    start = hash(@leaf_salt <> block_data)
    proven_r?(start, pth, pf)
  end

  defp proven_r?(curhash, [], [root]) do
    curhash == root
  end

  defp proven_r?(curhash, [p | pth], [h | pf]) do
    case p do
      0 -> proven_r?(hash(@node_salt <> curhash <> h), pth, pf)
      1 -> proven_r?(hash(@node_salt <> h <> curhash), pth, pf)
    end
  end
end
