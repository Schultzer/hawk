defmodule Hawk.Config do
  @moduledoc """
  The Hawk.Config implements two callbacks

  ## Examples

  ### `get_credential/2`
  A function to lookup the set of Hawk credentials based on the provided credentials id.
  The credentials include the MAC key, MAC algorithm, and other attributes (such as username)
  needed by the application. This function is the equivalent of verifying the username and
  password in Basic authentication.


      def get_credential(id)
        case Repo.get_by(Credentials, id: id) do
          %{id: ^id, algorithm: algorithm, key: key} = credentials -> credentials

          _ -> nil
        end
      end

  ### `nonce/3`
  Nonce validation function.

      def nonce(key, nonce, _ts) do
          case :ets.lookup(:used_nonce, :latest) do
            []                       -> :ets.insert(:used_nonce, latest: {key, nonce})

            [latest: {^key, ^nonce}] -> :error # Error on replay attack

            _                        -> :error
          end
      end
  """

  @type credentials :: %{algoritim: binary() | atom(), id: binary() | integer(), key: binary()}
  @callback nonce(binary(), binary(), binary() | integer()) :: :ok | :error
  @callback get_credentials(term(), Hawk.opts()) :: credentials | nil

  @doc false
  defmacro __using__(_) do
    quote do
      @behaviour unquote(__MODULE__)

      def nonce(key, nonce, ts), do: :ok

      defoverridable unquote(__MODULE__)
    end
  end
end
