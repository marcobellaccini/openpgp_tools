defmodule PacketTypeTest.CompressedDataTest do
  use ExUnit.Case
  alias OpenpgpTools.PacketTypes.CompressedData, as: CD

  ## Tests for parse function
  test "pt_compressed_data_parse_basic" do
    body = [<<1>>, <<0xFA>>, <<0x2B>>]
    parsed = body |> CD.parse
    assert parsed.alg == :zip
    assert parsed.cdata == [<<0xFA>>, <<0x2B>>]
  end

  ## Tests for get_alg function
  test "pt_compressed_data_get_alg_basic" do
    assert :uncom == CD.get_alg(<<0>>)
    assert :zip == CD.get_alg(<<1>>)
    assert :zlib == CD.get_alg(<<2>>)
    assert :bzip2 == CD.get_alg(<<3>>)
    assert :private == CD.get_alg(<<100>>)
  end

  test "pt_compressed_data_get_alg_bad" do
    assert_raise(RuntimeError, "Error: unknown compression algorithm",
                  fn -> CD.get_alg(<<20>>) end )
  end

end
