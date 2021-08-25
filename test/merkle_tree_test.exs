defmodule MerkleTreeTest do
  use ExUnit.Case
  doctest Merkle.Tree

  test "New empty tree" do
    assert %Merkle.Tree{root: root, height: ht} = Merkle.Tree.new()
    assert ht == 0
    assert %Merkle.Node{hash: hsh, children: []} = root
    assert hsh == Merkle.Tree.leaf_hash("")
  end

  test "New one-item tree" do
    assert %Merkle.Tree{root: root, height: ht} = Merkle.Tree.new(["foobar"])
    assert ht == 0
    assert %Merkle.Node{hash: hsh, children: []} = root
    assert hsh == Merkle.Tree.leaf_hash("foobar")
  end

  test "Two item tree" do
    t =  Merkle.Tree.new(["a", "b"])
    assert %Merkle.Tree{root: _root, height: 1} = t
    assert Merkle.Tree.size(t) == 2
  end

  test "Three item tree" do
    t = Merkle.Tree.new(["a", "b", "c"])
    assert Merkle.Tree.size(t) == 4
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
    assert ["a", "b", "c", ""]
    |> Enum.with_index(fn data,i -> {i, data} end)
    |> Enum.all?(fn {ind,data} ->
      Merkle.Tree.verify_proof(
        Merkle.Tree.gen_proof(t, ind),
        t,
        ind,
        Merkle.Tree.leaf_hash(data)
      )
    end)
  end
end
