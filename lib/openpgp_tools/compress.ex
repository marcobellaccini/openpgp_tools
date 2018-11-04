defmodule OpenpgpTools.Compress do
  use Private

  @doc """
  Given compressed data and compression algorithm (as a map),
  return decompressed data.

  Valid values for compression algorithm are:
  `:zip`, `:zlib`, `:bzip2`, `:uncom`

  Ref: https://tools.ietf.org/html/rfc4880#section-5.6
       https://tools.ietf.org/html/rfc4880#section-9.3

  ## Example

        iex> pkt1 =
        ...>     File.stream!("test/fixtures/gpg2_1/bin/sign/test.txt.gpg") |>
        ...>        OpenpgpTools.Packet.parse_packet
        iex> pkt1.type
        :cdata
        iex> parsed_body = pkt1.body |>
        ...>        OpenpgpTools.PacketTypes.CompressedData.parse
        iex> Map.keys(parsed_body)
        [:alg, :cdata]
        iex> parsed_body.alg
        :zip
        iex> subdata = OpenpgpTools.Compress.decompress(parsed_body)
        iex> # let's explore the decompressed packet
        iex> subpkt1 = subdata |> OpenpgpTools.Packet.parse_packet
        iex> subpkt1.type
        :opsig

  """
  # no data to decompress
  def decompress(%{cdata: [], alg: _alg}),
    do: raise "Error: no data to decompress"
  # no compression
  def decompress(%{cdata: cdata, alg: :uncom}), do: cdata
  # zip
  def decompress(%{cdata: cdata, alg: :zip}) do
    # convert data to bytes type
    cdatab = cdata |> lsbe_to_bin
    # from a comment in GPG sources (g10/compress.c):
    # <<PGP uses a windowsize of 13 bits. Using a negative value for
    # it forces zlib not to expect a zlib header.  This is a
    # undocumented feature Peter Gutmann told me about.
    #
    # We must use 15 bits for the inflator because CryptoEx uses 15
    # bits thus the output would get scrambled w/o error indication
    # if we would use 13 bits.  For the uncompressing this does not
    # matter at all.>>
    z = :zlib.open()
    :zlib.inflateInit(z, -15)
    decomp = :zlib.inflate(z, cdatab)
    :zlib.close(z)
    # back to list of single-byte elements
    decomp |> binl_to_lsbe
  end
  # zlib
  def decompress(%{cdata: cdata, alg: :zlib}) do
    # convert data to bytes type
    cdatab = cdata |> lsbe_to_bin
    # decompress data with zlib headers and checksum
    decomp = [:zlib.uncompress(cdatab)]
    # back to list of single-byte elements
    decomp |> binl_to_lsbe
  end
  # bzip2
  def decompress(%{cdata: _cdata, alg: :bzip2}), do:
    raise "Sorry, bzip2 compression is not supported yet"
  # private, experimental or unknown
  def decompress(%{cdata: _cdata, alg: _alg}), do:
    raise "Error: unknown compression algorithm"
  # everything else
  def decompress(_), do:
    raise "Error: bad decompress call"

  private do
    # convert a list of bytes to a list of single-byte elements
    # e.g. [<<224, 88, 32>>, <<11, 16>>] ->
    # [<<224>>, <<88>>, <<32>>, <<11>>, <<16>>]
    defp binl_to_lsbe(data) do
      data
        |> Enum.map(&(:binary.bin_to_list(&1)))
        |> List.flatten
        |> Enum.map(&(:binary.encode_unsigned(&1)))
    end

    # convert a list of single-byte elements to byte type
    # e.g. [<<224>>, <<88>>, <<32>>, <<11>>, <<16>>] ->
    # <<224, 88, 32, 11, 16>>
    defp lsbe_to_bin(data) do
        data
          |> Enum.map(&(:binary.decode_unsigned(&1)))
          |> :binary.list_to_bin
    end
  end

end
