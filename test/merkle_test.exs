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
    trc = t.root.children
    trcl = hd(trc).children
    assert pf == Enum.map(trcl ++ trc ++ [t.root], fn x -> x.hash end)
  end

  test "verify proof" do
    t = Merkle.new(["a", "b", "c"])
    pf = Merkle.proof(t, 1)
    assert Merkle.proven?(t, 1, pf)
  end
end
