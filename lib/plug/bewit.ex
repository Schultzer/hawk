defmodule Plug.Bewit do
  @moduledoc """
  Authenticate a Bewit request

  ## Options
    * `:host_header_name` See `Plug.Bewit.host_header_name()`
    * `:localtime_offset_msec` See `Hawk.localtime_offset_msec()`
    * `:host` host name override
    * `:port` port override
  """

  @typedoc """
  Used to override the default `host` header when used
  behind a cache of a proxy. Apache2 changes the value of the 'Host' header while preserving
  the original (which is what the module must verify) in the 'x-forwarded-host' header field.
  """
  @type host_header_name :: iodata()

  @behaviour Plug

  alias Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, opts) do
    auth = Keyword.get(opts, :auth, [])
    credentials_fn = Keyword.get(opts, :credentials_fn, [])

    conn
    |> Hawk.Request.new(auth)
    |> authenticate(credentials_fn, opts)
    |> handle_error(conn)
  end

  defp authenticate({:error, reason}, _credentials_fn, _options), do: {:error, reason}
  defp authenticate(request, credentials_fn, options) do
    Hawk.Server.authenticate_bewit(request, credentials_fn, options)
  end

  defp handle_error({:error, {401, msg, {header, value}}}, conn) do
    conn
    |> Conn.put_resp_header(header, value)
    |> Conn.resp(401, msg)
    |> Conn.halt()
  end
  defp handle_error({:error, {status, msg}}, conn) do
    conn
    |> Conn.resp(status, msg)
    |> Conn.halt()
  end
  defp handle_error({:ok, _result}, conn) do
    Conn.resp(conn, 200, "")
  end
end
