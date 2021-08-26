defmodule MerkleKVTest do
  use ExUnit.Case

  test "new empty" do
    mkv = Merkle.KV.new()
    assert Merkle.KV.size(mkv) == 0
  end

  test "new" do
    es = [{"a", "foo"}, {"b", "bar"}, {"a", "baz"}]
    mkv = Merkle.KV.new(es)
    assert {"a", "baz"} == Merkle.KV.get(mkv, "a")
  end

  test "put" do
    es = [{"a", "foo"}, {"b", "bar"}, {"c", "blort"}]
    mkv = Merkle.KV.new(es)
    assert {"a", "foo"} == Merkle.KV.get(mkv, "a")
    mkv2 = Merkle.KV.put(mkv, {"a", "baz"})
    assert {"a", "baz"} == Merkle.KV.get(mkv2, "a")
  end

  # &&& test proofs

end
