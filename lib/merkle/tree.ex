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

  defp height(ln) do
    if ln == 0, do: 1, else: ceil(:math.log2(ln))
  end

  @spec new([binary()]) :: Merkle.Tree.t()
  def new(blocks \\ []) do
    ln = length(blocks)
    ht = height(ln)
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

  @spec gen_membership_proof(Merkle.Tree.t(), non_neg_integer()) :: [hash_t()]
  def gen_membership_proof(t = %Merkle.Tree{root: root}, ind) do
    pth = path(t, ind)
    _gen_membership_proof(root, pth, [])
  end

  defp _gen_membership_proof(%Merkle.Node{}, [], pf), do: pf
  defp _gen_membership_proof(%Merkle.Node{children: children}, [p | pth], pf) do
    [l, r] = children
    case p do
      0 -> _gen_membership_proof(l, pth, [r.hash | pf])
      1 -> _gen_membership_proof(r, pth, [l.hash | pf])
    end
  end

  @spec verify_membership_proof([hash_t()], hash_t(), non_neg_integer(), hash_t()) :: boolean()
  @doc """
  Verifies that proof _proof_hashes_ correctly proves that _xi_ is the _ind_ event in Merkle
  tree with root hash _root_hash_
  """
  def verify_membership_proof(proof_hashes, root_hash, ind, xi) do
    _verify_membership_proof(xi, ind, proof_hashes) == root_hash
  end

  defp _verify_membership_proof(curhash, _n, []), do: curhash

  defp _verify_membership_proof(curhash, n, [h | hashes]) do
    case n &&& 1 do
      0 -> _verify_membership_proof(node_hash(curhash, h), n >>> 1, hashes)
      1 -> _verify_membership_proof(node_hash(h, curhash), n >>> 1, hashes)
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

  @spec gen_incremental_proof(Merkle.Tree.t(), non_neg_integer(), non_neg_integer()) :: Merkle.Node.t()
  @doc """
  Return a proof that version i of tree t is consistent with version j, where j >= i
  """
  def gen_incremental_proof(t = %Merkle.Tree{}, i, j) do
    _skeleton(t, i, j)
  end

  defp _skeleton(t = %Merkle.Tree{}, i, j) do
    pi = path(t, i)
    pj = path(t, j)
    _skel(t.root, pi, pj)
    #_skeleton(t.root, pi, pj)
  end

  defp _skeleton(node, [], []), do: node
  defp _skeleton(node, [i | pi], [j | pj]) do
    [l, r] = node.children
    case {i,j} do
      {0, 0} -> build_node(_skeleton(l, pi, pj), stub_node(r))
      {1, 1} -> build_node(stub_node(l), _skeleton(r, pi, pj))
      {0, 1} -> build_node(_skeleton_left(l, pi), _skeleton_right(r, pj))
      {1, 0} -> raise ArgumentError
    end
  end

  defp _skeleton_left(node, []), do: node
  defp _skeleton_left(node, [i | pi]) do
    [l, r] = node.children
    case i do
      0 -> build_node(_skeleton_left(l, pi), stub_node(r))
      1 -> build_node(stub_node(l), _skeleton_left(r, pi))
    end
  end

  defp _skeleton_right(node, []), do: node
  defp _skeleton_right(node, [i | pi]) do
    [l, r] = node.children
    case i do
      0 -> build_node(_skeleton_right(l, pi), stub_node(r))
      1 -> build_node(stub_node(l), _skeleton_right(r, pi))
    end
  end

  defp stub_node(node) do
    case node.children do
      [] -> node
      [_l, _r] -> %Merkle.Node{hash: node.hash, children: []}
    end
  end


  defp _skel(%Merkle.Node{children: [l,r]}, [i | pi], [j | pj]) do
    case {i,j} do
      {0, 0} -> _skel(l, pi, pj)
      {1, 1} -> _skel(r, pi, pj)
      {0, 1} -> _skel_left(l, pi) ++  _skel_right(r, pj)
      {1, 0} -> raise ArgumentError
    end
  end

  defp _skel_left(%Merkle.Node{children: [l,r]}, [0]), do: [l.hash, r.hash]
  defp _skel_left(%Merkle.Node{children: [l,r]}, [1]), do: [r.hash, l.hash]
  defp _skel_left(%Merkle.Node{children: [l,r]}, [i | pi]) do
    case i do
      0 -> _skel_left(l, pi) ++ [r.hash]
      1 -> _skel_left(r, pi) ++ [l.hash]
    end
  end

  defp _skel_right(%Merkle.Node{children: [l,r]}, [0]), do: [l.hash, r.hash]
  defp _skel_right(%Merkle.Node{children: [l,r]}, [1]), do: [r.hash, l.hash]
  defp _skel_right(%Merkle.Node{children: [l,r]}, [i | pi]) do
    case i do
      0 -> _skel_right(l, pi) ++ [r.hash]
      1 -> _skel_right(r, pi) ++ [l.hash]
    end
  end


  @spec verify_incremental_proof([hash_t()], non_neg_integer(), non_neg_integer(), hash_t(), hash_t()) :: boolean()
  @doc """
  Verifies that proof _proof_hashes_ correctly proves that root hash _ci_ at index _i_ is
  consistent with a future tree with root hash _cj_ and index _j_
  """
  def verify_incremental_proof([xi| pf], i, j, ci, cj) do
    pth = Enum.reverse(path(i, height(i)))
    {ci_prime, pf} = _verify_ci_proof(pf, pth, xi, xi)
    IO.inspect {ci_prime, pf}
    ci_prime == ci
  end

  defp _verify_ci_proof(hashes, [], hsh), do: {hsh, hashes}
  defp _verify_ci_proof([proof_hash | hashes], [p | pth], cur_hash) do
    IO.puts "STEP #{cur_hash} #{proof_hash} #{p} #{inspect pth}"
    case p do
      0 -> _verify_ci_proof(hashes, pth, node_hash(proof_hash, cur_hash))
      1 -> _verify_ci_proof(hashes, pth, node_hash(cur_hash, null_hash(pth)))
    end
  end

  defp null_hash([_n]), do: leaf_hash(@default_data)
  defp null_hash([_n | pth]) do
    nh = null_hash(pth)
    node_hash(nh, nh)
  end
end
