defmodule Merkle.Tree do
  use Bitwise

  @moduledoc """
  Implementation of a Merkle tree data structure
  """

  defstruct [:root, :height, :size]
  @type t :: %__MODULE__ {
    root: Merkle.Node.t(),
    height: non_neg_integer(),
    size: non_neg_integer(),
  }

  @leaf_salt <<0>>
  @node_salt <<1>>
  @default_data ""
  @default_hash :crypto.hash(:sha256, @leaf_salt <> @default_data)
  |> Base.encode16(case: :lower)

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

  defp build_node(l, r) do
    %Merkle.Node{
      hash: node_hash(l.hash, r.hash),
      children: [l, r],
    }
  end

  @spec new([binary()]) :: Merkle.Tree.t()
  def new(blocks \\ []) do
    ln = length(blocks)
    ht = if ln == 0, do: 1, else: ceil(:math.log2(ln))
    full_ln = 1 <<< ht

    # pad out the blocks to length full_ln
    all_blocks = blocks ++ List.duplicate(@default_data, full_ln - ln)
    %Merkle.Tree{
      root: build_tree(full_ln, all_blocks),
      height: ht,
      size: ln,
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
    build_node(lt, rt)
  end

  @spec path(non_neg_integer | Merkle.Tree.t(), integer) :: [non_neg_integer()]
  def path(%Merkle.Tree{height: ht}, i) when i < (1 <<< ht), do: path(ht, i)
  def path(ht, i) when is_integer(ht) do
    p = Integer.digits(i, 2)
    List.duplicate(0, ht-length(p)) ++ p
  end

  @spec gen_membership_proof(Merkle.Tree.t(), non_neg_integer()) :: Merkle.Proof.t()
  def gen_membership_proof(t = %Merkle.Tree{root: root}, ind) do
    pth = path(t, ind)
    %Merkle.Proof{
      id: ind,
      hashes: _gen_membership_proof(root, pth, [root.hash]),
    }
  end

  defp _gen_membership_proof(%Merkle.Node{}, [], pf), do: pf
  defp _gen_membership_proof(%Merkle.Node{children: children}, [p | pth], pf) do
    [l, r] = children
    case p do
      0 -> _gen_membership_proof(l, pth, [r.hash | pf])
      1 -> _gen_membership_proof(r, pth, [l.hash | pf])
    end
  end

  @spec verify_membership_proof(Merkle.Proof.t(), Merkle.Tree.t(), non_neg_integer(), hash_t()) :: boolean()
  @doc """
  Verifies that pf correctly proves that xi is the ind-th event in Merkle tree t
  """
  def verify_membership_proof(%Merkle.Proof{id: proof_ind, hashes: hashes}, t = %Merkle.Tree{root: root}, ind, xi) do
    pth = path(t, ind) |> Enum.reverse()
    proof_root = List.last(hashes)
    proof_root == root.hash && proof_ind == ind && _verify_membership_proof(xi, pth, hashes)
  end

  defp _verify_membership_proof(curhash, [], [root_hash]) do
    curhash == root_hash
  end

  defp _verify_membership_proof(curhash, [p | pth], [h | pf]) do
    case p do
      0 -> _verify_membership_proof(node_hash(curhash, h), pth, pf)
      1 -> _verify_membership_proof(node_hash(h, curhash), pth, pf)
    end
  end

  # this only works on a full tree
  defp double_size(t = %Merkle.Tree{size: sz, height: ht}) when sz == (1 <<< ht) do
    dummies = List.duplicate(@default_data, sz)
    rt = build_tree(sz, dummies)
    root = build_node(t.root, rt)
    %Merkle.Tree{
      root: root,
      height: ht + 1,
      size: sz,
    }
  end

  @spec add(Merkle.Tree.t(), binary()) :: Merkle.Tree.t()
  def add(t = %Merkle.Tree{size: sz, height: ht}, block)
    when sz == (1 <<< ht), do: add(double_size(t), block)

  def add(%Merkle.Tree{root: root, size: sz, height: ht}, block) do
    pth = path(ht, sz)
    IO.inspect(pth)
    %Merkle.Tree{
      root: _add(root, pth, block),
      height: ht,
      size: sz + 1,
    }
  end

  # only replace a default node -- never a filled node
  defp _add(%Merkle.Node{hash: hsh}, [], block) when hsh == @default_hash do
    build_leaf(block)
  end

  defp _add(%Merkle.Node{children: children}, [p | pth], block) do
    [l, r] = children
    case p do
      0 -> build_node(_add(l, pth, block), r)
      1 -> build_node(l, _add(r, pth, block))
    end
  end
end
