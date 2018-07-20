defmodule Hawk do
  @moduledoc """
  Documentation for Hawk.
  """

  @typedoc false
  @type algorithm :: atom() | charlist() | binary()

  @typedoc false
  @type request :: %{method: binary(), url: binary(), host: binary(), port: pos_integer() | binary(), authorization: binary(), content_type: binary()}

  @typedoc false
  @type method :: :delete | :get | :patch | :post | :put

  @typedoc false
  @type credentials :: %{algorithm: algorithm(), id: binary(), key: binary()}

  @typedoc """
  A function to lookup the set of Hawk credentials based on the provided credentials id.
  The credentials include the MAC key, MAC algorithm, and other attributes (such as username)
  needed by the application. This function is the equivalent of verifying the username and
  password in Basic authentication.

  ## Example
      fn id ->
        case Repo.get_by(Credentials, id: id) do
          nil -> :error

          %{id: id, algorithm: algorithm, key: key} = credentials -> credentials
        end
      end
  """
  @type credentials_fn :: function()

  @typedoc """
  Nonce validation function

  ## Example
      fn (key, nonce, _ts) ->
          case :ets.lookup(:used_nonce, :latest) do
            []                       -> :ets.insert(:used_nonce, latest: {key, nonce})

            [latest: {^key, ^nonce}] -> :error # Error on replay attack

            _                        -> :error
          end
      end
  """
  @type nonce_fn :: function()

  @typedoc """
  Number of seconds of permitted clock skew for incoming timestamps. Defaults to 60 seconds.
  Provides a +/- skew which means actual allowed window is double the number of seconds.
  """
  @type timestamp_skew_sec :: integer()

  @typedoc """
  Local clock time offset express in a number of milliseconds (positive or negative). Defaults to 0.
  """
  @type localtime_offset_msec :: integer()
end
