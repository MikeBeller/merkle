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

  @type hash_t :: String.t()
  @spec hash(binary()) :: hash_t()
  def hash(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end

  @spec leaf_hash(binary()) :: hash_t()
  def leaf_hash(data), do: hash(@leaf_salt <> data)

  @spec node_hash(binary(), binary()) :: hash_t()
  def node_hash(a, b), do: hash(@node_salt <> a <> b)

  defp build_leaf(data) do
      %Merkle.Node{
        hash: leaf_hash(data),
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
      hash: node_hash(lt.hash, rt.hash),
      children: [lt, rt],
    }
  end

  @spec path(non_neg_integer | Merkle.t(), integer) :: [non_neg_integer()]
  def path(%Merkle{height: ht}, i) when i < (1 <<< ht), do: path(ht, i)
  def path(ht, i) when is_integer(ht) do
    p = Integer.digits(i, 2)
    List.duplicate(0, ht-length(p)) ++ p
  end

  @spec proof(Merkle.t(), non_neg_integer()) :: Merkle.Proof.t()
  def proof(t = %Merkle{root: root}, ind) do
    pth = path(t, ind)
    %Merkle.Proof{
      id: ind,
      hashes: _proof(root, pth, [root.hash]),
    }
  end

  defp _proof(%Merkle.Node{}, [], pf), do: pf
  defp _proof(%Merkle.Node{children: children}, [p | path], pf) do
    [l, r] = children
    case p do
      0 -> _proof(l, path, [r.hash | pf])
      1 -> _proof(r, path, [l.hash | pf])
    end
  end

  @spec proven?(Merkle.Proof.t(), Merkle.t(), non_neg_integer(), hash_t()) :: boolean()
  @doc """
  Verifies that pf correctly proves that xi is the ind-th event in Merkle tree t
  """
  def proven?(%Merkle.Proof{id: id, hashes: hashes}, t = %Merkle{}, ind, xi) do
    pth = path(t, ind) |> Enum.reverse()
    id == ind && leaf_hash(Enum.at(t.blocks, ind)) == xi && _proven?(xi, pth, hashes)
  end

  defp _proven?(curhash, [], [root]) do
    curhash == root
  end

  defp _proven?(curhash, [p | pth], [h | pf]) do
    case p do
      0 -> _proven?(node_hash(curhash, h), pth, pf)
      1 -> _proven?(node_hash(h, curhash), pth, pf)
    end
  end
end
