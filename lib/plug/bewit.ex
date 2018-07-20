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

  alias Plug.{Conn, Conn.Status}
  use Plug.ErrorHandler

  def init(opts) do
    opts
  end

  def call(conn, opts) do
    auth = Keyword.get(opts, :auth, [])
    credentials_fn = Keyword.get(opts, :credentials_fn, [])

    conn
    |> Hawk.Request.new(auth)
    |> Hawk.Server.authenticate_bewit(credentials_fn, opts)

    Conn.resp(conn, 200, "authenticated")
  end

  def handle_errors(conn, %{kind: _kind, reason: %Hawk.Unauthorized{plug_status: status, header: header}, stack: _stack}) do
    conn
    |> Conn.put_resp_header("www-authenticate", header)
    |> Conn.send_resp(status, Status.reason_phrase(status))
  end
  def handle_errors(conn, %{kind: _kind, reason: %{plug_status: status}, stack: _stack}) do
    Conn.send_resp(conn, status, Status.reason_phrase(status))
  end
end
