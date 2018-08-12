defmodule Hawk.URI do
  @moduledoc false

  @doc false
  @spec authenticate(Hawk.request(), function(), keyword() | map()) :: {:ok, %{attributes: map(), credentials: map()}} | {:error, term()}
  defdelegate authenticate(req, credentials_fn, options \\ []), to: Hawk.Server, as: :authenticate_bewit

  @doc false
  @spec get_bewit(binary() | URI.t(), Hawk.Client.credentials(), integer(), keyword() | map()) :: %{artifacts: map, bewit: binary()}
  defdelegate get_bewit(uri, credentials, ttl_sec, options \\ []), to: Hawk.Client
end
