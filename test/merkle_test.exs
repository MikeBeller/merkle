defmodule MerkleTest do
  use ExUnit.Case
  doctest Merkle

  test "New empty tree" do
    assert %Merkle{root: root, blocks: blocks, height: ht} = Merkle.new()
    assert ht == 0
    assert %Merkle.Node{hash: hash, children: []} = root
    assert [""] = blocks
    assert hash == :crypto.hash(:sha256, <<0>> <> "") |> Base.encode16(case: :lower)
  end

  test "New one-item tree" do
    assert %Merkle{root: root, blocks: blocks, height: ht} = Merkle.new(["foobar"])
    assert ht == 0
    assert %Merkle.Node{hash: hash, children: []} = root
    assert ["foobar"] = blocks
    assert hash == :crypto.hash(:sha256, <<0>> <> "foobar") |> Base.encode16(case: :lower)
  end

  test "Two item tree" do
    assert %Merkle{root: _root, blocks: blocks, height: ht} = Merkle.new(["a", "b"])
    assert ht == 1
    assert length(blocks) == 2
  end

  test "Three item tree" do
    assert %Merkle{root: _root, blocks: blocks, height: ht} = Merkle.new(["a", "b", "c"])
    assert ht == 2
    assert length(blocks) == 4
  end

  test "path" do
    t = Merkle.new(["a", "b", "c", "d", "e"])
    assert Merkle.path(t, 0) == [0, 0, 0]
    assert Merkle.path(t, 1) == [0, 0, 1]
    assert Merkle.path(t, 7) == [1, 1, 1]
  end

  test "proof" do
    t = Merkle.new(["a", "b", "c"])
    pf = Merkle.proof(t, 1)
    #IO.inspect t
    #IO.inspect pf
    [kid_l, kid_r] = t.root.children
    [gc_l, _gc_r] = kid_l.children
    assert pf == Enum.map([gc_l, kid_r, t.root], &(&1.hash))
  end

  test "verify proof" do
    t = Merkle.new(["a", "b", "c"])
    pf = Merkle.proof(t, 1)
    assert Merkle.proven?("b", 1, pf)
    assert !Merkle.proven?("x", 1, pf)

    # check them all
    assert (t.blocks
    |> Enum.with_index(fn bl,ind ->
      Merkle.proven?(bl, ind, Merkle.proof(t, ind)) end)
      |> Enum.all?())
  end
end
