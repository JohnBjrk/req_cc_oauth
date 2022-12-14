defmodule ReqClientCredentialsAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :req_client_credentials_auth,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
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
      {:req, "~> 0.3.0"},
      {:bypass, "~> 2.1", only: :test}
    ]
  end
end
