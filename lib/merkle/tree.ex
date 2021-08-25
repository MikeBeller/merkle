defmodule Merkle.Tree do
  use Bitwise

  @moduledoc """
  Implementation of a Merkle tree data structure
  """

  defstruct [:root, :height]
  @type t :: %__MODULE__ {
    root: Merkle.Node.t(),
    height: non_neg_integer(),
  }

  @spec size(Merkle.Tree.t()) :: non_neg_integer
  def size(%Merkle.Tree{height: height}) do
    1 <<< height
  end

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

  @spec new() :: Merkle.Tree.t()
  def new do
    new([@default_data])
  end

  @spec new(list) :: Merkle.Tree.t()
  def new(blocks) when is_list(blocks) do
    ln = length(blocks)
    ht = ceil(:math.log2(ln))
    full_ln = 1 <<< ht

    # pad out the blocks to length full_ln
    all_blocks = blocks ++ List.duplicate("", full_ln - ln)
    %Merkle.Tree{
      root: build_tree(full_ln, all_blocks),
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

  @spec path(non_neg_integer | Merkle.Tree.t(), integer) :: [non_neg_integer()]
  def path(%Merkle.Tree{height: ht}, i) when i < (1 <<< ht), do: path(ht, i)
  def path(ht, i) when is_integer(ht) do
    p = Integer.digits(i, 2)
    List.duplicate(0, ht-length(p)) ++ p
  end

  @spec gen_proof(Merkle.Tree.t(), non_neg_integer()) :: Merkle.Proof.t()
  def gen_proof(t = %Merkle.Tree{root: root}, ind) do
    pth = path(t, ind)
    %Merkle.Proof{
      id: ind,
      hashes: _gen_proof(root, pth, [root.hash]),
    }
  end

  defp _gen_proof(%Merkle.Node{}, [], pf), do: pf
  defp _gen_proof(%Merkle.Node{children: children}, [p | path], pf) do
    [l, r] = children
    case p do
      0 -> _gen_proof(l, path, [r.hash | pf])
      1 -> _gen_proof(r, path, [l.hash | pf])
    end
  end

  @spec verify_proof(Merkle.Proof.t(), Merkle.Tree.t(), non_neg_integer(), hash_t()) :: boolean()
  @doc """
  Verifies that pf correctly proves that xi is the ind-th event in Merkle tree t
  """
  def verify_proof(%Merkle.Proof{id: proof_ind, hashes: hashes}, t = %Merkle.Tree{root: root}, ind, xi) do
    pth = path(t, ind) |> Enum.reverse()
    proof_root = List.last(hashes)
    proof_root == root.hash && proof_ind == ind && _verify_proof(xi, pth, hashes)
  end

  defp _verify_proof(curhash, [], [root_hash]) do
    curhash == root_hash
  end

  defp _verify_proof(curhash, [p | pth], [h | pf]) do
    case p do
      0 -> _verify_proof(node_hash(curhash, h), pth, pf)
      1 -> _verify_proof(node_hash(h, curhash), pth, pf)
    end
  end
end
