defmodule MerkleTest do
  use ExUnit.Case
  #doctest Merkle

  test "New empty tree" do
    assert %Merkle{root: root, blocks: blocks} = Merkle.new()
    assert %Merkle.Node{hash: hash, children: []} = root
    assert [""] = blocks
    assert hash == :crypto.hash(:sha256, <<0>> <> "") |> Base.encode16(case: :lower)
  end

  test "New one-item tree" do
    assert %Merkle{root: root, blocks: blocks} = Merkle.new(["foobar"])
    assert %Merkle.Node{hash: hash, children: []} = root
    assert ["foobar"] = blocks
    assert hash == :crypto.hash(:sha256, <<0>> <> "foobar") |> Base.encode16(case: :lower)
  end

  test "Two item tree" do
    assert %Merkle{root: _root, blocks: blocks} = Merkle.new(["a", "b"])
    assert length(blocks) == 2
  end

  test "Three item tree" do
    assert %Merkle{root: _root, blocks: blocks} = Merkle.new(["a", "b", "c"])
    assert length(blocks) == 4
  end
end
