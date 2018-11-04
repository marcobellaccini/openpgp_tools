defmodule OpenpgpTools.PacketTypes.CompressedData do
  use Private

  @doc """
  Given a list containing binary packet body data, return a map containing:
  - compression algorithm
  - compressed data (as a list of binaries)

  Possible values for compression algorithm are:
  `:zip`, `:zlib`, `:bzip2`, `:uncom`, `:private`

  Ref: https://tools.ietf.org/html/rfc4880#section-5.6
       https://tools.ietf.org/html/rfc4880#section-9.3

  ## Example

        iex> pkt1 = File.stream!("test/fixtures/gpg2_1/bin/sign/test.txt.gpg") |>
        ...>        OpenpgpTools.Packet.parse_packet
        iex> pkt1.type
        :cdata
        iex> parsed_body = pkt1.body |>
        ...>        OpenpgpTools.PacketTypes.CompressedData.parse
        iex> Map.keys(parsed_body)
        [:alg, :cdata]
        iex> parsed_body.alg
        :zip
        iex> length(parsed_body.cdata)
        364

  """
  def parse(body) do
    %{alg: get_alg(Enum.at(body, 0)), cdata: Enum.drop(body, 1)}
  end

  private do
    defp get_alg(<<0>>), do: :uncom
    defp get_alg(<<1>>), do: :zip
    defp get_alg(<<2>>), do: :zlib
    defp get_alg(<<3>>), do: :bzip2
    defp get_alg(<<n>>) when n in 100..110, do: :private
    defp get_alg(_), do: raise "Error: unknown compression algorithm"
  end

end
