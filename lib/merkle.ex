defmodule Merkle do
  use Bitwise

  @moduledoc """
  Implementation of a Merkle tree
  """

  defstruct [:root, :blocks, :height]

  @leaf_salt <<0>>
  @node_salt <<1>>
  @default_data ""

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

  def new do
    new([@default_data])
  end

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

  def path(%Merkle{height: ht}, i) when i < (1 <<< ht) do
    p = Integer.digits(i, 2)
    List.duplicate(0, ht-length(p)) ++ p
  end

  def proof(t = %Merkle{root: root}, ind) do
    pth = path(t, ind)
    proof(root, pth, [root.hash])
  end

  def proof(%Merkle.Node{}, [], pf), do: pf
  def proof(%Merkle.Node{children: children}, [b | rest], pf) do
    [l, r] = children
    pf = [l.hash | [r.hash | pf]]
    proof((if b == 0, do: l, else: r), rest, pf)
  end

  # not right -- need to reverse order if the path bit was a 1
  def proven?(_t = %Merkle{}, _ind, pf) do
    Enum.chunk_every(pf, 3, 2, :discard)
    |> Enum.reduce(true, fn
      [lh,rh,nh], v ->
        v && (hash(@node_salt <> lh <> rh) == nh)
    end)
  end
end
