defmodule Hawk.URI do
  @moduledoc false

  @doc false
  @spec authenticate(Hawk.request(), Hawk.credentials_fn(), Enumerable.t()) :: %{credentials: map(), attributes: map()} | no_return()
  defdelegate authenticate(req, credentials_fn, options \\ []), to: Hawk.Server, as: :authenticate_bewit

  @doc false
  @spec get_bewit(binary() | URI.t(), Hawk.Client.credentials(), integer(), Enumerable.t()) :: %{artifacts: map, bewit: binary()}
  defdelegate get_bewit(uri, credentials, ttl_sec, options \\ []), to: Hawk.Client
end
