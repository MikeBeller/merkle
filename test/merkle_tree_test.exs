defmodule MerkleTreeTest do
  use ExUnit.Case

  test "New empty tree" do
    assert %Merkle.Tree{root: _root, height: ht, size: sz} = Merkle.Tree.new()
    assert ht == 1
    assert sz == 0
  end

  test "New one-item tree" do
    assert %Merkle.Tree{root: root, height: ht} = Merkle.Tree.new(["foobar"])
    assert ht == 0
    assert %Merkle.Node{hash: hsh, children: []} = root
    assert hsh == Merkle.Tree.leaf_hash("foobar")
  end

  test "Two item tree" do
    t =  Merkle.Tree.new(["a", "b"])
    assert %Merkle.Tree{root: _root, height: 1, size: sz} = t
    assert sz == 2
  end

  test "Three item tree" do
    t = Merkle.Tree.new(["a", "b", "c"])
    assert t.size == 3
  end

  test "path" do
    t = Merkle.Tree.new(["a", "b", "c", "d", "e"])
    assert Merkle.Tree.path(t, 0) == [0, 0, 0]
    assert Merkle.Tree.path(t, 1) == [0, 0, 1]
    assert Merkle.Tree.path(t, 7) == [1, 1, 1]
    assert t.size == 5
  end

  test "proof" do
    t = Merkle.Tree.new(["a", "b", "c"])
    pf = Merkle.Tree.gen_membership_proof(t, 1)
    [kid_l, kid_r] = t.root.children
    [gc_l, _gc_r] = kid_l.children
    assert pf == Enum.map([gc_l, kid_r], &(&1.hash))
  end

  test "verify proof" do
    t = Merkle.Tree.new(["a", "b", "c"])
    pf = Merkle.Tree.gen_membership_proof(t, 1)
    assert Merkle.Tree.verify_membership_proof(pf, t.root.hash, 1, Merkle.Tree.leaf_hash("b"))
    assert !Merkle.Tree.verify_membership_proof(pf, t.root.hash, 1, Merkle.Tree.leaf_hash("x"))

    # check them all
    assert ["a", "b", "c", ""]
    |> Enum.with_index(fn data,i -> {i, data} end)
    |> Enum.all?(fn {ind,data} ->
      Merkle.Tree.verify_membership_proof(
        Merkle.Tree.gen_membership_proof(t, ind),
        t.root.hash,
        ind,
        Merkle.Tree.leaf_hash(data)
      )
    end)
  end

  test "add" do
    t = Merkle.Tree.new(["a", "b", "c"])
    pf = Merkle.Tree.gen_membership_proof(t, 1)
    assert Merkle.Tree.verify_membership_proof(pf, t.root.hash, 1, Merkle.Tree.leaf_hash("b"))
    t2 = Merkle.Tree.add(t, "d")
    pf2 = Merkle.Tree.gen_membership_proof(t2, 3)
    assert Merkle.Tree.verify_membership_proof(pf2, t2.root.hash, 3, Merkle.Tree.leaf_hash("d"))
  end

  test "add when full" do
    t = Merkle.Tree.new(["a", "b", "c", "d"])
    pf = Merkle.Tree.gen_membership_proof(t, 1)
    assert Merkle.Tree.verify_membership_proof(pf, t.root.hash, 1, Merkle.Tree.leaf_hash("b"))

    t2 = Merkle.Tree.add(t, "e")
    assert t2.size == 5
    assert t2.height == t.height + 1
    pf2 = Merkle.Tree.gen_membership_proof(t2, 4)
    assert Merkle.Tree.verify_membership_proof(pf2, t2.root.hash, 4, Merkle.Tree.leaf_hash("e"))
  end

  test "incremental proof" do
    t1 = Merkle.Tree.new(["a", "b", "c"])
    t2 = Merkle.Tree.new(["a", "b", "c", "d","e","f","g"])
    i = 2
    j = 6
    ci = t1.root.hash
    cj = t2.root.hash
    pf = Merkle.Tree.gen_incremental_proof(t2, i, j)
    IO.inspect t2.root
    IO.puts "Proof: #{inspect pf}"
    IO.inspect Merkle.Tree.verify_incremental_proof(pf, i, j, ci, cj)
  end
end
