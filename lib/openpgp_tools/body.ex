defmodule OpenpgpTools.Body do
  use Private

  @doc """
  Given packet body data and packet type, parse packet body.

  Returned values depends on packet type.

  ## Example

        iex> pkt1 =
        ...>    File.stream!("test/fixtures/gpg2_1/bin/sign/test.txt.gpg") |>
        ...>        OpenpgpTools.Packet.parse_packet
        iex> pkt1.type
        :cdata
        iex> parsed_body = OpenpgpTools.Body.parse_body(pkt1.body, pkt1.type)
        iex> Map.keys(parsed_body)
        [:alg, :cdata]
        iex> parsed_body.alg
        :zip
        iex> length(parsed_body.cdata)
        364

  """
  def parse_body(body, :cdata), do:
    OpenpgpTools.PacketTypes.CompressedData.parse(body)
  def parse_body(_body, _type), do: raise "Error: cannot parse this packet body"

end
