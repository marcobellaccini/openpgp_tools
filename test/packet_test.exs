defmodule FileParserTest do
  use ExUnit.Case
  alias OpenpgpTools.Packet, as: PK
  alias OpenpgpTools.Base64, as: B64

  # function to generate n bytes of test data
  # it returns a list of bytes
  def tdata(n), do: for i <- 1..n, do: << rem(i, 256) >>

  ## Tests for parse_ptag function

  # From: https://tools.ietf.org/html/rfc4880#section-4.2
  # Bit 7 -- Always one
  test "parse_ptag_bad_bit7" do
    assert_raise(RuntimeError, "Bad packet tag: bit 7 must be one",
                 fn -> PK.parse_ptag(<< 0::size(1), 0::size(7) >>) end )
  end

  # test old packet format, one-octect length-type
  test "parse_ptag_old_pf_1oct" do
    ptagb = << 1::size(1), 0::size(1), 9::size(4), 0::size(2) >>
    tag = ptagb |> PK.parse_ptag
    assert {:old, :sedata, :oneoct} == tag
  end

  # test old packet format, two-octect length-type
  test "parse_ptag_old_pf_2oct" do
    ptagb = << 1::size(1), 0::size(1), 9::size(4), 1::size(2) >>
    tag = ptagb |> PK.parse_ptag
    assert {:old, :sedata, :twooct} == tag
  end

  # test old packet format, four-octect length-type
  test "parse_ptag_old_pf_4oct" do
    ptagb = << 1::size(1), 0::size(1), 9::size(4), 2::size(2) >>
    tag = ptagb |> PK.parse_ptag
    assert {:old, :sedata, :fouroct} == tag
  end

  # test old packet format, indeterminate length-type
  test "parse_ptag_old_pf_indet" do
    ptagb = << 1::size(1), 0::size(1), 9::size(4), 3::size(2) >>
    tag = ptagb |> PK.parse_ptag
    assert {:old, :sedata, :indet} == tag
  end

  # test new packet format
  test "parse_ptag_new_pf" do
    ptagb = << 1::size(1), 1::size(1), 63::size(6) >>
    tag = ptagb |> PK.parse_ptag
    assert {:new, :private, :none} == tag
  end

  ## Tests for binl_to_intl function
  test "binl_to_intl_basic" do
    binl = [<<1>>, <<2>>, <<3>>]
    intl = binl |> PK.binl_to_intl
    assert [1, 2, 3] == intl
  end

  ## Tests for get_blen function

  # old packet format
  test "get_blen_old_1_oct" do
    packet = [<< 1::size(1), 0::size(1), 1::size(4), 0::size(2) >>,
              << 0x64 >> ]
    blen = packet |> PK.get_blen
    assert [ 100 ] == blen
  end

  test "get_blen_old_2_oct" do
    packet = [<< 1::size(1), 0::size(1), 1::size(4), 1::size(2) >>,
              << 0x64 >>, << 0x64 >> ]
    blen = packet |> PK.get_blen
    assert [ 25_700 ] == blen
  end

  test "get_blen_old_4_oct" do
    packet = [<< 1::size(1), 0::size(1), 1::size(4), 2::size(2) >>,
              << 0x64 >>, << 0x64 >>, << 0x64 >>, << 0x64 >> ]
    blen = packet |> PK.get_blen
    assert [ 1_684_300_900 ] == blen
  end

  test "get_blen_old_ind" do
    data = tdata(34)
    packet = [<< 1::size(1), 0::size(1), 1::size(4), 3::size(2) >>
              | data ]
    blen = packet |> PK.get_blen
    assert [ 34 ] == blen
  end

  # new packet format
  test "get_blen_new_1_oct" do
    packet = [<< 1::size(1), 1::size(1), 1::size(6) >>,
              << 0x64 >> ]
    blen = packet |> PK.get_blen
    assert [ 100 ] == blen
  end

  test "get_blen_new_2_oct" do
    packet = [<< 1::size(1), 1::size(1), 1::size(6) >>,
              << 0xC5 >>, << 0xFB >> ]
    blen = packet |> PK.get_blen
    assert [ 1723 ] == blen
  end

  test "get_blen_new_5_oct" do
    packet = [<< 1::size(1), 1::size(1), 1::size(6) >>,
              << 0xFF >>, << 0x00 >>, << 0x01 >>, << 0x86 >>, << 0xA0 >> ]
    blen = packet |> PK.get_blen
    assert [ 100000 ] == blen
  end

  test "get_blen_new_partlen" do
    packet = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 0xEF >> ,
              tdata(32768), << 0xE1 >>, tdata(2), << 0xE0 >>, tdata(1),
              << 0xF0 >>, tdata(65536), << 0xC5 >>, << 0xDD >> ,
              tdata(1693) ] |> List.flatten
    blen = packet |> PK.get_blen
    assert [ 1693, 65536, 1, 2, 32768 ] == blen
  end

  ## Tests for get_hlen function

  # old packet format
  test "get_hlen_old_1_oct" do
    assert 2 == PK.get_hlen(:oneoct, << 0x64 >>)
  end

  test "get_hlen_old_2_oct" do
    assert 3 == PK.get_hlen(:twooct, << 0x64 >>)
  end

  test "get_hlen_old_4_oct" do
    assert 5 == PK.get_hlen(:fouroct, << 0x64 >>)
  end

  test "get_hlen_old_ind" do
    assert 1 == PK.get_hlen(:indet, << 0x64 >>)
  end

  # new packet format
  test "get_hlen_new_1_oct" do
    assert 2 == PK.get_hlen(:none, << 191 >>)
  end

  test "get_hlen_new_2_oct" do
    assert 3 == PK.get_hlen(:none, << 223 >>)
  end

  test "get_hlen_new_5_oct" do
    assert 6 == PK.get_hlen(:none, << 255 >>)
  end

  test "get_hlen_new_partlen" do
    assert 2 == PK.get_hlen(:none, << 254 >>)
  end

  ## Tests for parse_type function
  test "get_parse_type_ok" do
    ptype = 2 |> PK.parse_type
    assert :sig == ptype
  end

  test "get_parse_type_fail" do
    assert_raise(RuntimeError, "Unknown packet type",
                 fn -> PK.parse_type(489) end )
  end

  ## Tests for get_lpl_new_np function
  test "get_lpl_new_np_basic" do
    assert 1 == PK.get_lpl_new_np(191)
    assert 2 == PK.get_lpl_new_np(8383)
    assert 5 == PK.get_lpl_new_np(4_294_967_295)
    assert_raise(RuntimeError, "Cannot infer length of packet length field",
                 fn -> PK.get_lpl_new_np(4_294_967_296) end )
  end

  ## Tests for get_pbody function
  # non-partial body lengths
  test "get_pbody_nplen" do
    data = tdata(100)
    bli = [100]
    packet = [<< 1::size(1), 1::size(1), 1::size(6) >>,
              << 100 >>] ++ data
    assert data == PK.get_pbody(packet, bli)
    data2 = tdata(1723)
    bli2 = [1723]
    packet2 = [<< 1::size(1), 1::size(1), 1::size(6) >>,
              << 0xC5 >>, << 0xFB >>] ++ data2
    assert data2 == PK.get_pbody(packet2, bli2)
  end

  # partial body lengths
  test "get_pbody_plen" do
    packet = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 0xEF >> ,
              tdata(32768), << 0xE1 >>, tdata(2), << 0xE0 >>, tdata(1),
              << 0xF0 >>, tdata(65536), << 0xC5 >>, << 0xDD >> ,
              tdata(1693) ] |> List.flatten
    data = tdata(32768) ++ tdata(2) ++ tdata(1) ++ tdata(65536) ++ tdata(1693)
    bli = [1693, 65536, 1, 2, 32768]
    assert data == PK.get_pbody(packet, bli)
  end

  ## Tests for get_pack_len function
  # non-partial body lengths
  test "get_pack_len_nplen" do
    # if we have a packet like this:
    # [<< ptag >>, << 100 >>] ++ data100bytes
    assert 102 == PK.get_pack_len(2, [100])
    # if we have a packet like this:
    # [<< ptag >>, << 0xC5 >>, << 0xFB >>] ++ data1723bytes
    assert 1726 == PK.get_pack_len(3, [1723])
  end

  # partial body lengths
  test "get_pack_len_plen" do
    # if we have a packet like this:
    # [<< 1::size(1), 1::size(1), 1::size(6) >>, << 0xEF >> ,
    #           tdata(32768), << 0xE1 >>, tdata(2), << 0xE0 >>, tdata(1),
    #           << 0xF0 >>, tdata(65536), << 0xC5 >>, << 0xDD >> ,
    #           tdata(1693) ] |> List.flatten
    bli = [1693, 65536, 1, 2, 32768]
    assert Enum.sum(bli) + 7 == PK.get_pack_len(2, bli)
  end

  ### Tests for parse_packet function

  ## single packet
  # non-partial body lengths
  test "parse_packet_sp_nplen" do
    phead = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 100 >>]
    pbody = tdata(100)
    rawdata = phead ++ pbody
    parsed = PK.parse_packet(rawdata)
    pformat = :new
    ptype = :pkesk
    resdata = []
    assert %{format: pformat, type: ptype, header: phead, body: pbody,
            residual: resdata} == parsed
  end
  # partial body lengths
  test "parse_packet_sp_plen" do
    phead = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 0xEF >>]
    pbody = [tdata(32768), << 0xE1 >>, tdata(2), << 0xE0 >>, tdata(1),
            << 0xF0 >>, tdata(65536), << 0xC5 >>, << 0xDD >> ,
            tdata(1693)] |> List.flatten
    pbody_purged = [tdata(32768), tdata(2), tdata(1),
            tdata(65536), tdata(1693)] |> List.flatten
    rawdata = phead ++ pbody
    parsed = PK.parse_packet(rawdata)
    pformat = :new
    ptype = :pkesk
    resdata = []
    assert %{format: pformat, type: ptype, header: phead, body: pbody_purged,
            residual: resdata} == parsed
  end
  ## multiple packet
  # non-partial body lengths
  test "parse_packet_mp_nplen" do
    phead = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 100 >>]
    pbody = tdata(100)
    rawpdata = phead ++ pbody
    phead2 = [<< 1::size(1), 1::size(1), 3::size(6) >>, << 20 >>]
    pbody2 = tdata(20)
    rawpdata2 = phead2 ++ pbody2
    rawdata = rawpdata ++ rawpdata2
    parsed = PK.parse_packet(rawdata)
    pformat = :new
    ptype = :pkesk
    resdata = rawpdata2
    assert %{format: pformat, type: ptype, header: phead, body: pbody,
            residual: resdata} == parsed
  end
  # partial body lengths
  test "parse_packet_mp_plen" do
    phead = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 0xEF >>]
    pbody = [tdata(32768), << 0xE1 >>, tdata(2), << 0xE0 >>, tdata(1),
            << 0xF0 >>, tdata(65536), << 0xC5 >>, << 0xDD >> ,
            tdata(1693)] |> List.flatten
    pbody_purged = [tdata(32768), tdata(2), tdata(1),
            tdata(65536), tdata(1693)] |> List.flatten
    rawpdata = phead ++ pbody
    phead2 = [<< 1::size(1), 1::size(1), 3::size(6) >>, << 20 >>]
    pbody2 = tdata(20)
    rawpdata2 = phead2 ++ pbody2
    rawdata = rawpdata ++ rawpdata2
    parsed = PK.parse_packet(rawdata)
    pformat = :new
    ptype = :pkesk
    resdata = rawpdata2
    assert %{format: pformat, type: ptype, header: phead, body: pbody_purged,
            residual: resdata} == parsed
  end

  # feed function with a list of multiple-bytes elements
  test "parse_packet_mb_list" do
    phead = [<< 1::size(1), 1::size(1), 1::size(6) >>, << 0xEF >>]
    pbody = [tdata(32768), << 0xE1 >>, tdata(2), << 0xE0 >>, tdata(1),
            << 0xF0 >>, tdata(65536), << 0xC5 >>, << 0xDD >> ,
            tdata(1693)] |> List.flatten
    pbody_purged = [tdata(32768), tdata(2), tdata(1),
            tdata(65536), tdata(1693)] |> List.flatten
    rawdata = phead ++ pbody
    rawdatau = Enum.map(rawdata, &(:binary.decode_unsigned(&1)))
    {rawdata_p1, rawdata_p2} = Enum.split(rawdatau, 3)
    rawdata_p1_b = :binary.list_to_bin(rawdata_p1)
    rawdata_p2_b = :binary.list_to_bin(rawdata_p2)
    parsed = PK.parse_packet([rawdata_p1_b, rawdata_p2_b])
    pformat = :new
    ptype = :pkesk
    resdata = []
    assert %{format: pformat, type: ptype, header: phead, body: pbody_purged,
            residual: resdata} == parsed
  end

  # feed function with empty list
  test "parse_packet_empty_list" do
    assert_raise(RuntimeError, "Error: no data to parse",
                 fn -> PK.parse_packet([]) end )
  end

  # real data tests - encrypted file
  test "parse_packet_rd_enc_file" do
    pkt1 = File.stream!("test/fixtures/gpg2_1/bin/encr/test.txt.gpg") |>
           PK.parse_packet
    pkt1_exp = File.read!("test/fixtures/gpg2_1/bin/encr/pkt1.dump") |>
               :erlang.binary_to_term
    assert pkt1 == pkt1_exp
    pkt2 = pkt1.residual |> PK.parse_packet
    pkt2_exp = File.read!("test/fixtures/gpg2_1/bin/encr/pkt2.dump") |>
               :erlang.binary_to_term
    assert pkt2 == pkt2_exp
    assert pkt2.residual == []
  end

  # real data tests - signed file
  test "parse_packet_rd_sig_file" do
    pkt1 = File.stream!("test/fixtures/gpg2_1/bin/sign/test.txt.gpg") |>
           PK.parse_packet
    pkt1_exp = File.read!("test/fixtures/gpg2_1/bin/sign/pkt1.dump") |>
               :erlang.binary_to_term
    assert pkt1 == pkt1_exp
    assert pkt1.residual == []
  end

  # interoperability with base64 module
  test "parse_packet_rd_b64" do
    pkt1 = File.stream!("test/fixtures/gpg2_1/b64/encr/test.txt.asc") |>
           B64.to_binl |>
           PK.parse_packet
    assert pkt1.format == :old
  end

end
