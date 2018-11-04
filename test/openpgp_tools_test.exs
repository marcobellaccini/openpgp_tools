defmodule OpenpgpToolsTest do
  use ExUnit.Case
  doctest OpenpgpTools

  test "greets the world" do
    assert OpenpgpTools.hello() == :world
  end
end
