defmodule OpenpgpTools.Base64 do
  use Private

  @doc """
  Given an OpenPGP Base64-encoded armored data stream, return a list containing
  raw, binary data.

  See: https://tools.ietf.org/html/rfc4880#section-6

  ## Example

      iex> bdata = File.stream!("test/fixtures/gpg2_1/b64/encr/test.txt.asc") |>
      ...>         OpenpgpTools.Base64.to_binl
      iex> pkt1 = bdata |> OpenpgpTools.Packet.parse_packet
      iex> Map.keys(pkt1)
      [:body, :format, :header, :residual, :type]

  """
  def to_binl([]), do: raise ("Error: no data to convert")
  def to_binl(stream) do
    fpart = stream |>
      Enum.map(&(String.trim(&1, " "))) |> # trim white-spaces
      Enum.map(&(String.trim_trailing(&1, "\n"))) |> # trim trailing newline
      Enum.map(&(String.trim_trailing(&1, "\r"))) |> # ...and CR (for CR-LF EOL)
      Enum.drop_while(&(not armor_head_tail?(&1))) |> # skip to armor head
      Enum.drop_while(&(not blank?(&1))) |> # skip to blank line
      Enum.drop(1) # drop empty line

    adata_cs_b64 = fpart # armor data and checksum
      |> Enum.take_while(&(not armor_head_tail?(&1)))

    # get armored data and checksum
    {adata_b64_tj, cs_b64} = adata_cs_b64 |>
                          Enum.split_while(&(not String.starts_with?(&1, "=")))

    # decode armored data
    bdata = Base.decode64!(Enum.join(adata_b64_tj))

    # decode checksum
    bcs = Base.decode64!(Enum.at(cs_b64, 0) |>
                         String.trim_leading("="))

    # check checksum
    check_checksum_crc24(bdata, bcs)

    # return binary data in a list
    [bdata]

  end

  private do
    # check for armor header line
    defp armor_head_tail?(st) do
      String.starts_with?(st, "-----") and String.ends_with?(st, "-----")
    end
    # check if blank line
    defp blank?(st) do
      "" == (st |> String.trim)
    end
    # get crc24 checksum
    defp get_checksum_crc24(data) do
      # compute checksum
      crcopt = %{
                  width: 24,
                  poly: 0x864CFB,
                  init: 0xB704CE,
                  refin: false,
                  refout: false,
                  xorout: 0x00
                }
      :binary.encode_unsigned(CRC.calculate(data, crcopt))
    end
    # check crc24 checksum
    defp check_checksum_crc24(data, e_checksum) do
      # compute checksum
      cs = get_checksum_crc24(data)
      # raise exception if bad checksum
      raise_if_false(cs == e_checksum, "Error: bad checksum for base64 data")
    end
    # raise if true
    defp raise_if_false(false, msg), do: raise msg
    defp raise_if_false(true, _msg), do: :ok
  end
end
