defmodule Hawk.Mixfile do
  use Mix.Project

  @version "0.2.0"

  def project do
    [
      app: :hawk,
      version: @version,
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:sntp, "~> 0.2.1"},
      {:kryptiles, "~> 0.1.0"},
      {:plug, ">= 0.0.0", optional: true},
      {:ex_doc, "~> 0.14", only: :dev}
    ]
  end

  defp docs() do
    [
      extras: ["README.md"],
      main: "readme",
      groups_for_modules: groups_for_modules(),
      source_ref: "v#{@version}",
      source_url: "https://github.com/schultzer/hawk"
    ]
  end

  defp groups_for_modules() do
    [
      Hawk:  [Hawk.Client, Hawk.Server, Hawk.Crypto],
      Plugs: [Plug.Hawk, Plug.Bewit]
    ]
  end
end
