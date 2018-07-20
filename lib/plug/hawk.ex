defmodule Plug.Hawk do
  @moduledoc """
  Authenticate a Hawk request

  ## Options
    ## Required
    * `:credentials_fn` See `Hawk.credentials_fn()`

    ## Optional
    * `:auth`
      * `:host_header_name` See `Plug.Hawk.host_header_name()`
      * `:nonce_fn` See `Hawk.nonce_fn()`
      * `:timestamp_skew_sec` See `Hawk.timestamp_skew_sec()`
      * `:localtime_offset_msec` See `Hawk.localtime_offset_msec()`
      * `:payload` See `Hawk.Server.payload()`
      * `:host` host name override
      * `:port` port override

    * `:header`
      * `:ext` Application specific data sent via the ext attribute
      * `:payload` UTF-8 encoded string for body hash generation (ignored if hash provided)
      * `:content_type` Payload content-type (ignored if hash provided)
      * `:hash` Pre-calculated payload hash
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
    header = Keyword.get(opts, :header, [])

    conn
    |> Hawk.Request.new(auth)
    |> Hawk.Server.authenticate(opts[:credentials_fn], auth)
    |> Hawk.Server.header(header)
    |> put_header(conn)
  end

  @spec put_header(binary(), Conn.t()) :: Conn.t()
  def put_header(header, conn) do
    conn
    |> Conn.put_resp_header("server-authorization", header)
    |> Conn.resp(200, "authenticated")
  end

  def handle_errors(conn, %{kind: _kind, reason: %Hawk.Unauthorized{plug_status: status, header: header, message: msg}, stack: _stack}) do
    conn
    |> Conn.put_resp_header("www-authenticate", header)
    |> Conn.send_resp(status, msg)
  end
  def handle_errors(conn, %{kind: _kind, reason: %{plug_status: status}, stack: _stack}) do
    Conn.send_resp(conn, status, Status.reason_phrase(status))
  end
end
