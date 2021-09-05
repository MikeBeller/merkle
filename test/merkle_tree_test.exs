defmodule MerkleTreeTest do
  use ExUnit.Case

  alias Merkle.Tree

  test "New empty tree" do
    assert %Tree{root: _root, height: ht, size: sz} = Tree.new()
    assert ht == 1
    assert sz == 0
  end

  test "New one-item tree" do
    assert %Tree{height: ht, size: sz} = Tree.new(["foobar"])
    assert ht == 0
    assert sz == 1
  end

  test "Two item tree" do
    t =  Tree.new(["a", "b"])
    assert %Tree{root: _root, height: 1, size: sz} = t
    assert sz == 2
  end

  test "Three item tree" do
    t = Tree.new(["a", "b", "c"])
    assert t.size == 3
  end

  test "path" do
    t = Tree.new(["a", "b", "c", "d", "e"])
    assert Tree.path(t, 0) == [0, 0, 0]
    assert Tree.path(t, 1) == [0, 0, 1]
    assert Tree.path(t, 7) == [1, 1, 1]
    assert t.size == 5
  end

  test "proof" do
    t = Tree.new(["a", "b", "c"])
    pf = Tree.gen_membership_proof(t, 1)
    [kid_l, kid_r] = t.root.children
    [gc_l, _gc_r] = kid_l.children
    assert pf == Enum.map([gc_l, kid_r], &(&1.hash))
  end

  test "verify proof" do
    t = Tree.new(["a", "b", "c"])
    pf = Tree.gen_membership_proof(t, 1)
    assert Tree.verify_membership_proof(pf, t.root.hash, 1, Tree.leaf_hash("b"))
    assert !Tree.verify_membership_proof(pf, t.root.hash, 1, Tree.leaf_hash("x"))

    # check them all
    assert ["a", "b", "c", ""]
    |> Enum.with_index(fn data,i -> {i, data} end)
    |> Enum.all?(fn {ind,data} ->
      Tree.verify_membership_proof(
        Tree.gen_membership_proof(t, ind),
        t.root.hash,
        ind,
        Tree.leaf_hash(data)
      )
    end)
  end

  test "add" do
    t = Tree.new(["a", "b", "c"])
    pf = Tree.gen_membership_proof(t, 1)
    assert Tree.verify_membership_proof(pf, t.root.hash, 1, Tree.leaf_hash("b"))
    t2 = Tree.add(t, "d")
    pf2 = Tree.gen_membership_proof(t2, 3)
    assert Tree.verify_membership_proof(pf2, t2.root.hash, 3, Tree.leaf_hash("d"))
  end

  test "isomorphism of add" do
    t0 = Tree.new()
    t1 = Tree.new(["a"])
    assert Tree.add(t0, "a") == t1

    t1 = Tree.new(["a","b","c"])
    t2 = Tree.new(["a"])
    |> Tree.add("b")
    |> Tree.add("c")
    assert t1 == t2
    t3 = Tree.new()
    |> Tree.add("a")
    |> Tree.add("b")
    |> Tree.add("c")
    assert t1 == t3
  end

  test "add when full" do
    t = Tree.new(["a", "b", "c", "d"])
    pf = Tree.gen_membership_proof(t, 1)
    assert Tree.verify_membership_proof(pf, t.root.hash, 1, Tree.leaf_hash("b"))

    t2 = Tree.add(t, "e")
    assert t2.size == 5
    assert t2.height == t.height + 1
    pf2 = Tree.gen_membership_proof(t2, 4)
    assert Tree.verify_membership_proof(pf2, t2.root.hash, 4, Tree.leaf_hash("e"))
  end

  test "incremental proof" do
    t1 = Tree.new(["a", "b", "c"])
    t2 = Tree.new(["a", "b", "c", "d","e","f","g"])
    i = 2
    j = 6
    ci = t1.root.hash
    cj = t2.root.hash
    #IO.puts "C1"
    #IO.inspect t1.root
    pf = Tree.gen_incremental_proof(t2, i, j)
    #IO.puts "C2"
    #IO.inspect t2.root
    #IO.puts "Proof:"
    #IO.inspect pf
    assert Tree.verify_incremental_proof(pf, i, j, ci, cj)
  end

  test "from nothing to something" do
    t1 = Tree.new()
    t2 = Tree.add(t1, "a")
    assert t2.size == 1
  end

  test "incremental proof from zero" do
    t1 = Tree.new(["a"])
    t2 = Tree.new(["a", "b"])
    pr = Tree.gen_incremental_proof(t2, 0, 1)
    assert Tree.verify_incremental_proof(pr, 0, 1, t1.root.hash, t2.root.hash)
  end

  test "incremental proof from zero to larger size" do
    t1 = Tree.new(["a"])
    t2 = Tree.new(["a", "b", "c"])
    pr = Tree.gen_incremental_proof(t2, 0, 2)
    assert Tree.verify_incremental_proof(pr, 0, 2, t1.root.hash, t2.root.hash)
  end

  test "messy proof" do
    data = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]
    trees = Enum.scan(data, Tree.new([]),
      fn xi,tr -> Tree.add(tr, xi) end
    )

    nth = Enum.at(trees, 11)
    assert nth == Tree.new(data)

    for {i,j} <- [{2, 6}, {1,5}, {2, 11}, {1, 11}, {0,11}] do
      ti = Enum.at(trees, i)
      tj = Enum.at(trees, j)
      pf = Tree.gen_incremental_proof(tj, i, j)
      assert Tree.verify_incremental_proof(pf, i, j, ti.root.hash, tj.root.hash)
    end
  end
end
