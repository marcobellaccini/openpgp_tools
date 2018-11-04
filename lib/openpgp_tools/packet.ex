defmodule OpenpgpTools.Packet do
  use Private
  use Bitwise

  # Packet types map attribute.
  # See: https://tools.ietf.org/html/rfc4880#section-4.3
  @ptypes %{
    0 => :reserved, # Reserved
    1 => :pkesk, # Public-Key Encrypted Session Key Packet
    2 => :sig, # Signature Packet
    3 => :skesk, # Symmetric-Key Encrypted Session Key Packet
    4 => :opsig, # One-Pass Signature Packet
    5 => :seck, # Secret-Key Packet
    6 => :pubk, # Public-Key Packet
    7 => :secsubk, # Secret-Subkey Packet
    8 => :cdata, # Compressed Data Packet
    9 => :sedata, # Symmetrically Encrypted Data Packet
    10 => :marker, # Marker Packet
    11 => :ldata, # Literal Data Packet
    12 => :trust, # Trust Packet
    13 => :uid, # User ID Packet
    14 => :pubsubk, # Public-Subkey Packet
    17 => :uattr, # User Attribute Packet
    18 => :seipdata, # Sym. Encrypted and Integrity Protected Data Packet
    19 => :moddetcode, # Modification Detection Code Packet
    60 => :private, # Private or Experimental Values
    61 => :private, # Private or Experimental Values
    62 => :private, # Private or Experimental Values
    63 => :private # Private or Experimental Values
  }

  # parse packet type function
  private do
    defp parse_type(x), do: @ptypes |> Map.get(x) |> _parse_type
    defp _parse_type(nil), do: raise "Unknown packet type"
    defp _parse_type(x), do: x
  end

  @doc """
  Given raw binary OpenPGP data stream, return a map containing:
  - format type
  - packet type
  - packet header raw data
  - packet body raw data (in the partial body lengths case,
    body is purged from all the intermediate body length fields)
  - trailing (residual) raw data

  Possible values for format type are:

  `:old`, `:new`

  See: https://tools.ietf.org/html/rfc4880#section-4.2

  Possible values for packet type are:

  `:reserved`, `:pkesk`, `:sig`, `:skesk`, `:opsig`, `:seck`, `:pubk`,
  `:secsubk`, `:cdata`, `:sedata`, `:marker`, `:ldata`, `:trust`, `:uid`,
  `:pubsubk`, `:uattr`, `:seipdata`, `:moddetcode`, `:private`

  See: https://tools.ietf.org/html/rfc4880#section-4.3

  ## Example

      iex> pkt1 = File.stream!("test/fixtures/gpg2_1/bin/encr/test.txt.gpg") |>
      ...>        OpenpgpTools.Packet.parse_packet
      iex> Map.keys(pkt1)
      [:body, :format, :header, :residual, :type]
      iex> pkt1.format
      :old
      iex> pkt1.type
      :pkesk
      iex> pkt1.header
      [<<133>>, <<1>>, "\f" ]
      iex> pkt1.body |> Enum.take(4)
      [<<3>>, <<166>>, "b", "1" ]
      iex> pkt1.residual |> Enum.take(4)
      [<<210>>, "V", <<1>>, "c" ]
      iex> pkt2 = pkt1.residual |> OpenpgpTools.Packet.parse_packet
      iex> pkt2.format
      :new
      iex> pkt2.type
      :seipdata

  """
  def parse_packet([]), do: raise ("Error: no data to parse")
  def parse_packet(stream) do
    # get list of single-byte elements
    data = stream
          |> Enum.map(&(:binary.bin_to_list(&1)))
          |> List.flatten
          |> Enum.map(&(:binary.encode_unsigned(&1)))
    # get packet tag octet and first octet of packet body length
    [ptag, bl1] = data |> Enum.take(2)
    # parse packet tag
    {pformat, ptype, plt} = parse_ptag(ptag)
    # get packet header length
    hlen = get_hlen(plt, bl1)
    # get packet header
    phead = data |> Enum.take(hlen)
    # get body length information
    bli = get_blen(data)
    # get packet length
    pack_len = get_pack_len(hlen, bli)
    # get packet and residual raw data
    {packet, resdata} = data |> Enum.split(pack_len)
    # get packet body
    pbody = get_pbody(packet, bli)

    # NOTE: remember that, for the partial body lengths case,
    #       packet header ++ packet body != packet

    # return map with results
    %{ format: pformat, type: ptype, header: phead, body: pbody,
      residual: resdata }

  end

  # Parse a Packet Tag octet (i.e. a byte), returning the packet format, type and,
  # for the old format, the body length type.
  #
  # Possible values for format are:
  #
  # `:old`, `:new`
  #
  # See: https://tools.ietf.org/html/rfc4880#section-4.2
  #
  # Possible values for type are:
  #
  # `:reserved`, `:pkesk`, `:sig`, `:skesk`, `:opsig`, `:seck`, `:pubk`,
  # `:secsubk`, `:cdata`, `:sedata`, `:marker`, `:ldata`, `:trust`, `:uid`,
  # `:pubsubk`, `:uattr`, `:seipdata`, `:moddetcode`, `:private`
  #
  # See: https://tools.ietf.org/html/rfc4880#section-4.3
  #
  # Possible values for the body length type are:
  #
  # `:oneoct`, `:twooct`, `:fouroct`, `:indet`, `:none`
  # (the latter is returned for the new format)
  #
  # See: https://tools.ietf.org/html/rfc4880#section-4.2
  #
  private do
    # handle old format packets
    # one-octect length-type
    defp parse_ptag(<< 1::size(1), 0::size(1), ptag::size(4), 0::size(2) >>),
      do: {:old, parse_type(ptag), :oneoct}
    # two-octect length-type
    defp parse_ptag(<< 1::size(1), 0::size(1), ptag::size(4), 1::size(2) >>),
      do: {:old, parse_type(ptag), :twooct}
    # four-octect length-type
    defp parse_ptag(<< 1::size(1), 0::size(1), ptag::size(4), 2::size(2) >>),
      do: {:old, parse_type(ptag), :fouroct}
    # indeterminate length-type
    defp parse_ptag(<< 1::size(1), 0::size(1), ptag::size(4), 3::size(2) >>),
      do: {:old, parse_type(ptag), :indet}

    # handle new format packets
    defp parse_ptag(<< 1::size(1), 1::size(1), ptag::size(6) >>),
      do: {:new, parse_type(ptag), :none}
    # bit 7 must be 1
    defp parse_ptag(_ptagb) do
      raise "Bad packet tag: bit 7 must be one"
    end
  end

  # convert a list of binaries to a list of integers.
  private do
    defp binl_to_intl(binl) do
      binl |> Enum.map( fn(<<ie>>) -> ie end )
    end
  end

  # get header length
  # need packet length type and first byte of packet body length as arguments
  private do
    # old format
    # one-octet packet length type
    defp get_hlen(:oneoct, _blen1), do: 2
    # two-octet packet length type
    defp get_hlen(:twooct, _blen1), do: 3
    # four-octet packet length type
    defp get_hlen(:fouroct, _blen1), do: 5
    # indeterminate packet length type
    defp get_hlen(:indet, _blen1), do: 1

    # new format
    # one-octet packet length
    defp get_hlen(:none, blen1) when blen1 < << 192 >>, do: 2
    # two-octet packet length
    defp get_hlen(:none, blen1) when blen1 < << 224 >>, do: 3
    # partial length
    defp get_hlen(:none, blen1) when blen1 < << 255 >>, do: 2
    # five-octet packet length
    defp get_hlen(:none, blen1) when blen1 == << 255 >>, do: 6

  end

  # Given a packet, return a list with information about its Body Length.
  #
  # In most cases, the returned value is a single-element list containing
  # the packet body length in bytes.
  #
  # However, when the packet makes use of Partial Body Lengths, the returned value
  # is a list of partial body lengths, in reversed order.
  #
  # Ref: https://tools.ietf.org/html/rfc4880#section-4.2
  #

  private do
    defp get_blen(packet) do
      {format, _tag, blt} = packet |> Enum.at(0) |> parse_ptag
      _get_blen(packet, format, blt, Enum.at(packet, 1), [])
    end

    # private, wrapped functions need some additional arguments:
    # - packet format
    # - body length type (this is for the old format, for the new one
    #   pass :none)
    # - 1st octet of body length
    # - a body-length accumulator list (passed to perform tail-call-optimization
    #   in the partial body lengths case - for the new format)

    ## old packet format, one-octet length
    defp _get_blen(packet, :old, :oneoct, _blen1, bla) do
      octets = packet |> Enum.slice(1, 1) |> binl_to_intl
      [ Enum.at(octets, 0) | bla ]
    end
    ## old packet format, two-octet length
    defp _get_blen(packet, :old, :twooct, _blen1, bla) do
      octets = packet |> Enum.slice(1, 2) |> binl_to_intl
      [ (Enum.at(octets, 0) <<< 8) + Enum.at(octets, 1) | bla ]
    end
    ## old packet format, four-octet length
    defp _get_blen(packet, :old, :fouroct, _blen1, bla) do
      octets = packet |> Enum.slice(1, 4) |> binl_to_intl
      [ (Enum.at(octets, 0) <<< 24) + (Enum.at(octets, 1) <<< 16) +
      (Enum.at(octets, 2) <<< 8) + Enum.at(octets, 3)
       | bla ]
    end
    ## old packet format, indeterminate length
    # this will assume that the packet spans to the end of the stream
    defp _get_blen(packet, :old, :indet, _blen1, bla) do
      [ packet |> Enum.drop(1) |> length
       | bla ]
    end

    ## new packet format

    # new packet format, one-octet lengths
    defp _get_blen(packet, :new, :none, blen1, bla) when blen1 < << 192 >> do
      octets = packet |> Enum.slice(1, 1) |> binl_to_intl
      [ Enum.at(octets, 0) | bla ]
    end
    # new packet format, two-octet lengths
    defp _get_blen(packet, :new, :none, blen1, bla) when blen1 < << 224 >> do
      octets = packet |> Enum.slice(1, 2) |> binl_to_intl
      [ ((Enum.at(octets, 0) - 192) <<< 8) + (Enum.at(octets, 1)) + 192 | bla ]
    end
    # new packet format, partial body lengths
    # https://tools.ietf.org/html/rfc4880#section-4.2.2.4
    defp _get_blen(packet, :new, :none, blen1, bla) when blen1 < << 255 >> do
      octets = packet |> Enum.slice(1, 1) |> binl_to_intl
      len_of_part = 1 <<< (Enum.at(octets, 0) &&& 0x1F)
      residual = packet |> Enum.drop(2 + len_of_part - 1)
      new_bla = [len_of_part | bla]
      _get_blen(residual, :new, :none, Enum.at(residual, 1), new_bla)
    end
    # new packet format, five-octet lengths
    defp _get_blen(packet, :new, :none, blen1, bla) when blen1 == << 255 >> do
      octets = packet |> Enum.slice(1, 5) |> binl_to_intl
      [ (Enum.at(octets, 1) <<< 24) ||| (Enum.at(octets, 2) <<< 16) |||
      (Enum.at(octets, 3) <<< 8) ||| Enum.at(octets, 4)
       | bla ]
    end
  end


  # get length of packet length field for new format
  # this is for the non-partial lengths case
  # need body length as argument
  private do
    defp get_lpl_new_np(blen) when blen < 192, do: 1
    defp get_lpl_new_np(blen) when blen < 8384, do: 2
    defp get_lpl_new_np(blen) when blen < 4_294_967_296, do: 5
    defp get_lpl_new_np(_blen), do:
      raise "Cannot infer length of packet length field"
  end

  # given header length and a body length info list, return packet length
  # (header and body)
  private do
    # non-partial lengths case
    # gross body length is:
    # body length + header_length
    defp get_pack_len(hl, [bl]), do: bl + hl
    # partial lengths case
    # gross body length is:
    # length of the last partial body length field +
    # + one byte for each remaining partial body length field +
    # + net body length (i.e.: sum of all partial body lengths)
    # + 1 (packet tag byte)
    defp get_pack_len(_hl, bli = [last_pbl | oth_bl]) do
      get_lpl_new_np(last_pbl) + length(oth_bl) + Enum.sum(bli) + 1
    end
  end


  # get packet body
  # need ONE raw packet (NOT raw data containing multiple packets!)
  # and body length info as arguments
  private do
    # wrapper function
    defp get_pbody(data, bli) do
      # call wrapped function
      _get_pbody(data, bli)
    end
    # handle all cases except partial body lengths
    defp _get_pbody(data, [blen]), do: data |> Enum.take(-blen)
    # partial body lengths (match body lengths lists with more than one element)
    defp _get_pbody(data, bli = [_last_blen | _oth]) do
      _get_pbody_pbl_tail(data, bli, [])
    end
    # match the end of a chain of partial body lengths
    defp _get_pbody_pbl_tail(data, [last_blen | oth_blen], part_body) do
      part_body_new = Enum.take(data, -last_blen) ++ part_body
      _get_pbody_pbl(Enum.drop(data, - last_blen - get_lpl_new_np(last_blen)),
                    oth_blen, part_body_new)
    end
    # match the beginning of a chain of partial body lengths
    defp _get_pbody_pbl(data, [first_blen], part_body) do
      Enum.take(data, -first_blen) ++ part_body
    end
    # match other parts of a chain of partial body lengths
    defp _get_pbody_pbl(data, [last_blen | oth_blen], part_body) do
      part_body_new = Enum.take(data, -last_blen) ++ part_body
      _get_pbody_pbl(Enum.drop(data, - last_blen - 1), oth_blen,
                    part_body_new)
    end

  end

end
