defmodule BodyTest do
  use ExUnit.Case
  alias OpenpgpTools.Body, as: BO
  alias OpenpgpTools.PacketTypes.CompressedData, as: CD

  ## Tests for parse_body function
  test "bd_parse_body_cdata" do
    body = [<<1>>, <<0xFA>>, <<0x2B>>]
    assert BO.parse_body(body, :cdata) == CD.parse(body)
  end
  test "bd_parse_body_bad" do
    body = [<<1>>, <<0xFA>>, <<0x2B>>]
    assert_raise(RuntimeError, "Error: cannot parse this packet body",
                  fn -> BO.parse_body(body, :verybad) end )
  end

end
