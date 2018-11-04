defmodule CompressTest do
  use ExUnit.Case
  alias OpenpgpTools.Compress, as: CO

  ## Tests for decompress function

  # no data
  test "comp_decompress_nodata" do
    assert_raise(RuntimeError, "Error: no data to decompress",
                     fn -> CO.decompress(%{cdata: [], alg: :zip}) end )
  end

  # bad call
  test "comp_decompress_badcall" do
    assert_raise(RuntimeError, "Error: bad decompress call",
                     fn -> CO.decompress([<<1>>]) end )
  end

  # no compression
  test "comp_decompress_nocomp" do
    cdt = %{cdata: [<<233>>, <<10>>], alg: :uncom}
    assert [<<233>>, <<10>>] == CO.decompress(cdt)
  end

  # zip
  test "comp_decompress_zip" do
    # create compressed data
    data = <<30, 220, 2>>
    z = :zlib.open()
    :zlib.deflateInit(z, 5, :deflated, -15, 8, :default)
    compd = :zlib.deflate(z, data, :finish) |> CO.binl_to_lsbe
    :zlib.close(z)
    assert [<<30>>, <<220>>, <<2>>] == CO.decompress(%{cdata: compd, alg: :zip})
  end

  # zlib
  test "comp_decompress_zlib" do
    # create compressed data
    data = <<30, 220, 2>>
    compd = [:zlib.compress(data)] |> CO.binl_to_lsbe
    assert [<<30>>, <<220>>, <<2>>] == CO.decompress(%{cdata: compd, alg: :zlib})
  end

  ## Tests for binl_to_lsbe function
  test "comp_binl_to_lsbe_basic" do
    binl = [<<224, 88, 32>>, <<11, 16>>]
    assert CO.binl_to_lsbe(binl) == [<<224>>, <<88>>, <<32>>, <<11>>, <<16>>]
  end

  ## Tests for lsbe_to_bin function
  test "comp_lsbe_to_bin_basic" do
    lsbe = [<<224>>, <<88>>, <<32>>, <<11>>, <<16>>]
    assert CO.lsbe_to_bin(lsbe) == <<224, 88, 32, 11, 16>>
  end

end
