defmodule OpenpgpTools.MixProject do
  use Mix.Project

  def project do
    [
      app: :openpgp_tools,
      version: "0.1.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      name: "openpgp_tools",
      source_url: "https://github.com/marcobellaccini/openpgp_tools",
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:private, "> 0.0.0"}, # makes private functions public when testing
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:crc, "~> 0.9.1"} # crc module
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
    ]
  end
end
