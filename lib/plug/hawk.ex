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

  alias Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, opts) do
    auth = Keyword.get(opts, :auth, [])
    header = Keyword.get(opts, :header, [])

    conn
    |> Hawk.Request.new(auth)
    |> authenticate(opts[:credentials_fn], auth)
    |> handle_error(conn, header)
  end

  def authenticate({:error, reason}, _credentials_fn, _options), do: {:error, reason}
  def authenticate(request, credentials_fn, options) do
    Hawk.Server.authenticate(request, credentials_fn, options)
  end

  def handle_error({:error, {401, msg, {header, value}}}, conn, _options) do
    conn
    |> Conn.put_resp_header(header, value)
    |> Conn.resp(401, msg)
    |> Conn.halt()
  end
  def handle_error({:error, {status, msg}}, conn, _options) do
    conn
    |> Conn.resp(status, msg)
    |> Conn.halt()
  end
  def handle_error({:ok, result}, conn, options) do
    conn
    |> Conn.put_resp_header("server-authorization", Hawk.Server.header(result, options))
    |> Conn.resp(200, "")
  end
end
