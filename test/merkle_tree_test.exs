defmodule MerkleTreeTest do
  use ExUnit.Case
  doctest Merkle.Tree

  test "New empty tree" do
    assert %Merkle.Tree{root: root, blocks: blocks, height: ht} = Merkle.Tree.new()
    assert ht == 0
    assert %Merkle.Node{hash: hash, children: []} = root
    assert %{0 => ""} = blocks
    assert hash == :crypto.hash(:sha256, <<0>> <> "") |> Base.encode16(case: :lower)
  end

  test "New one-item tree" do
    assert %Merkle.Tree{root: root, blocks: blocks, height: ht} = Merkle.Tree.new(["foobar"])
    assert ht == 0
    assert %Merkle.Node{hash: hash, children: []} = root
    assert %{0 => "foobar"} = blocks
    assert hash == :crypto.hash(:sha256, <<0>> <> "foobar") |> Base.encode16(case: :lower)
  end

  test "Two item tree" do
    assert %Merkle.Tree{root: _root, blocks: blocks, height: ht} = Merkle.Tree.new(["a", "b"])
    assert ht == 1
    assert map_size(blocks) == 2
  end

  test "Three item tree" do
    assert %Merkle.Tree{root: _root, blocks: blocks, height: ht} = Merkle.Tree.new(["a", "b", "c"])
    assert ht == 2
    assert map_size(blocks) == 4
  end

  test "path" do
    t = Merkle.Tree.new(["a", "b", "c", "d", "e"])
    assert Merkle.Tree.path(t, 0) == [0, 0, 0]
    assert Merkle.Tree.path(t, 1) == [0, 0, 1]
    assert Merkle.Tree.path(t, 7) == [1, 1, 1]
    assert Merkle.Tree.size(t) == 8
  end

  test "proof" do
    t = Merkle.Tree.new(["a", "b", "c"])
    pf = Merkle.Tree.gen_proof(t, 1)
    #IO.inspect t
    #IO.inspect pf
    [kid_l, kid_r] = t.root.children
    [gc_l, _gc_r] = kid_l.children
    assert pf.hashes == Enum.map([gc_l, kid_r, t.root], &(&1.hash))
  end

  test "verify proof" do
    t = Merkle.Tree.new(["a", "b", "c"])
    pf = Merkle.Tree.gen_proof(t, 1)
    assert Merkle.Tree.verify_proof(pf, t, 1, Merkle.Tree.leaf_hash("b"))
    assert !Merkle.Tree.verify_proof(pf, t, 1, Merkle.Tree.leaf_hash("x"))

    # check them all
    assert 0..(Merkle.Tree.size(t)-1)
    |> Enum.all?(fn ind ->
      Merkle.Tree.verify_proof(
        Merkle.Tree.gen_proof(t, ind),
        t,
        ind,
        Merkle.Tree.leaf_hash(Map.get(t.blocks,ind))
      )
    end)
  end
end
