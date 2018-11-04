defmodule DocTest do
  use ExUnit.Case
  doctest OpenpgpTools.Packet
  doctest OpenpgpTools.Base64
  doctest OpenpgpTools.Body
  doctest OpenpgpTools.PacketTypes.CompressedData
  doctest OpenpgpTools.Compress
end
