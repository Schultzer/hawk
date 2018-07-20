defmodule Hawk.Server do
  @moduledoc """
  This module provides functions to create response headers and authenticate request
  """

  @typedoc """
  Payload for validation. The client calculates the hash value and includes it via the `hash`
  header attribute. The server always ensures the value provided has been included in the request
  MAC. When this option is provided, it validates the hash value itself. Validation is done by calculating
  a hash value over the entire payload (assuming it has already be normalized to the same format and
  encoding used by the client to calculate the hash on request). If the payload is not available at the time
  of authentication, the `Hawk.Server.authenticate_payload/4` method can be used by passing it the credentials and
  `attributes.hash` returned from `Hawk.Server.authenticate/2`.
  """
  @type payload :: iodata()

  alias Hawk.{Crypto, Header, Now, Unauthorized, BadRequest, InternalServerError}
  @algorithms Crypto.algorithms()

  @doc """
  Authenticate a hawk request

  ## Options
    * `:nonce_fn` See `Hawk.nonce_fn()`
    * `:timestamp_skew_sec` See `Hawk.timestamp_skew_sec()`
    * `:localtime_offset_msec` See `Hawk.localtime_offset_msec()`
    * `:payload` See `Hawk.Server.payload()`
  ## Examples

      iex> credentials_fn = fn (_) -> %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"} end
      iex> Hawk.Server.authenticate(res, credentials_fn)
  """
  @spec authenticate(Hawk.request(), Hawk.credentials_fn(), Enumerable.t()) :: %{credentials: map(), artifacts: map()} | no_return()
  def authenticate(request, credentials_fn, options \\ %{})
  def authenticate(request, credentials_fn, options) when is_list(options), do: authenticate(request, credentials_fn, Map.new(options))
  def authenticate(%{method: method, host: host, port: port, url: url} = req, credentials_fn, options) do
    options = Map.merge(%{timestamp_skew_sec: 60}, options)
    now = Now.msec(options)
    case Header.parse(req[:authorization]) do
      %{id: id, ts: _, nonce: _, mac: mac} = attributes ->
        artifacts = Map.merge(attributes, %{method: method, host: host, port: port, resource: url})
        credentials = fetch_credentials(id, credentials_fn)

        ## Validate
        calculate_mac(artifacts, credentials, mac, "header")
        check_payload(artifacts, credentials, options)
        check_nonce(artifacts, credentials, options)
        check_timestamp_staleness(artifacts, credentials, now, options)

        %{artifacts: artifacts, credentials: credentials}

      _  -> BadRequest.error("Missing attributes")
    end
  end


  @doc """
  Authenticate a raw request payload hash - used when payload cannot be provided during `Hawk.Server.authenticate/3`
  the `credentials` and `artifacts` are received from `Hawk.Server.authenticate/3` the `content-type` is from the request

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate_payload(iodata(), map(), map(), iodata()) :: %{credentials: map(), artifacts: map()} | :bad_payload_hash
  def authenticate_payload(payload, %{algorithm: algorithm} = credentials, %{hash: hash} = artifacts, content_type) do
    algorithm
    |> Crypto.calculate_payload_hash(payload, content_type)
    |> Kryptiles.fixed_time_comparison(hash)
    |> case do
         false -> Unauthorized.error("Bad payload hash")

         true  -> %{credentials: credentials, artifacts: artifacts}
       end
  end

  @doc """
  Authenticate payload hash - used when payload cannot be provided during `Hawk.Server.authenticate/3`
  takes the payload hash calculated using Hawk.Crypto.calculate_payload_hash/3 and  `artifacts` received from `Hawk.Server.authenticate/3`

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate_payload_hash(binary(), map()) :: %{artifacts: map()} | :bad_payload_hash
  def authenticate_payload_hash(calculate_hash, %{hash: hash} = artifacts) do
    case Kryptiles.fixed_time_comparison(calculate_hash, hash) do
      false -> Unauthorized.error("Bad payload hash")

      true  -> %{artifacts: artifacts}
    end
  end

  @doc false
  @spec header(map(), Enumerable.t()) :: binary()
  def header(%{credentials: credentials, artifacts: artifacts}, options), do: header(credentials, artifacts, Map.new(options))

  @doc """
  Generate a Server-Authorization header for a given response
  takes `credentials` and `artifacts` received from `Hawk.Server.authenticate/3`

  ## Options
   * `:ext` Application specific data sent via the ext attribute
   * `:payload` UTF-8 encoded string for body hash generation (ignored if hash provided)
   * `:content_type` Payload content-type (ignored if hash provided)
   * `:hash` Pre-calculated payload hash

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec header(map(), map(), Enumerable.t()) :: binary() | no_return()
  def header(credentials, artifacts, options \\ %{})
  def header(credentials, artifacts, options) when is_list(options), do: header(credentials, artifacts, Map.new(options))
  def header(%{key: _key, algorithm: algorithm} = credentials, %{method: _, host: _, port: _, resource: _, ts: _, nonce: _, id: _,} = artifacts, %{hash: _} = options) when algorithm in @algorithms do
    options = Map.take(options, [:ext, :hash])
    artifacts = artifacts |> Map.drop([:ext, :hash, :mac]) |> Map.merge(options)
    maybe_add(artifacts, "Hawk mac=\"#{Crypto.calculate_mac("response", credentials, artifacts)}\"")
  end
  def header(%{key: _key, algorithm: algorithm} = credentials, %{method: _, host: _, port: _, resource: _, ts: _, nonce: _, id: _} = artifacts, %{payload: payload} = options) when algorithm in @algorithms do
    options = options |> Map.take([:ext]) |> Map.put(:hash, Crypto.calculate_payload_hash(algorithm, payload, options[:content_type]))
    artifacts = artifacts |> Map.drop([:ext, :hash, :mac]) |> Map.merge(options)
    maybe_add(artifacts, "Hawk mac=\"#{Crypto.calculate_mac("response", credentials, artifacts)}\"")
  end
  def header(%{key: _key, algorithm: algorithm} = credentials, %{method: _, host: _, port: _, resource: _, ts: _, nonce: _, id: _} = artifacts, options) when algorithm in @algorithms do
    options = Map.take(options, [:ext, :hash])
    artifacts = artifacts |> Map.drop([:ext, :hash, :mac]) |> Map.merge(options)
    maybe_add(artifacts, "Hawk mac=\"#{Crypto.calculate_mac("response", credentials, artifacts)}\"")
  end


  defp maybe_add(%{hash: hash, ext: ext}, string), do: <<string::binary(), ", hash=", ?", hash::binary(), ?", ", ext=", ?", Header.escape_attribute(ext)::binary(), ?">>
  defp maybe_add(%{hash: hash}, string), do: <<string::binary(), ", hash=", ?", hash::binary(), ?">>
  defp maybe_add(%{ext: ext}, string), do: <<string::binary(), ", ext=", ?", Header.escape_attribute(ext)::binary(), ?">>
  defp maybe_add(_, string), do: string

  @doc """
  Authenticate a Hawk bewit request

  ## Options
   * `:localtime_offset_msec` Local clock time offset express in a number of milliseconds (positive or negative). Defaults to 0.

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate_bewit(Hawk.request(), Hawk.credentials_fn(), Enumerable.t()) :: %{credentials: map(), attributes: map()} | no_return()
  def authenticate_bewit(request, credentials_fn, options \\ %{})
  def authenticate_bewit(request, credentials_fn, options) when is_list(options), do: authenticate_bewit(request, credentials_fn, Map.new(options))
  def authenticate_bewit(%{url: url}, _credentials_fn, _options) when byte_size(url) > 4096, do: BadRequest.error("Resource path exceeds max length")
  def authenticate_bewit(%{method: method}, _credentials_fn, _options) when method not in ["GET", "HEAD"], do: Unauthorized.error("Invalid method")
  def authenticate_bewit(%{authorization: authorization}, _credentials_fn, _options) when authorization !== [], do: BadRequest.error("Multiple authentications")
  def authenticate_bewit(req, credentials_fn, options) do
    options = Map.merge(%{timestamp_skew_sec: 60}, options)
    now = Now.msec(options)
    [bewit, url] = parse(req[:url], now)
    artifacts = %{ts: bewit[:exp], nonce: "", method: "GET", resource: url, host: req[:host], port: req[:port], ext: bewit[:ext]}
    credentials = fetch_credentials(bewit["id"], credentials_fn)

    ## Validate mac
    calculate_mac(artifacts, credentials, bewit[:mac], "bewit")

    %{credentials: credentials, attributes: bewit}
  end

  defp parse(binary, now, resource \\ <<>>)
  defp parse(<<>>, _now, _resource), do: BadRequest.error("Invalid bewit encoding")
  defp parse([], _now, _resource), do: BadRequest.error("Invalid bewit encoding")
  defp parse(<<_::binary-size(1), "bewit=">>, _now, _resource), do: Unauthorized.error("Empty bewit")
  defp parse([_, ?b, ?e, ?w, ?i, ?t, ?=], _now, _resource), do: Unauthorized.error("Empty bewit")
  defp parse(<<b::binary-size(1), "bewit=", bewit::binary()>>, now, resource) do
    resource = if b == "?", do: <<resource::binary(), b::binary()>>, else: resource
    bewit
    |> parse_bewit(resource)
    |> validate_bewit(now)
  end
  defp parse(<<b::binary-size(1), rest::binary()>>, now, resource) do
    parse(rest, now, <<resource::binary(), b::binary()>>)
  end

  defp parse_bewit(binary, resource, bewit \\ <<>>)
  defp parse_bewit(<<>>, resource, bewit), do: [bewit, String.trim(resource, "?")]
  defp parse_bewit(<<??, _::binary()>> = query, resource, bewit) when bewit !== <<>>, do: [bewit, resource <> query]
  defp parse_bewit(<<?&, query::binary()>>, resource, bewit) when bewit !== <<>>, do: [bewit, resource <> query]
  defp parse_bewit(<<b::binary-size(1), rest::binary()>>, resource, bewit) do
    parse_bewit(rest, resource, <<bewit::binary(), b::binary-size(1)>>)
  end

  defp validate_bewit([bewit, url], now) do
    bewit
    |> Base.url_decode64(padding: false)
    |> validate_bewit(now, url)
  end
  defp validate_bewit(:error, _now, _url), do: BadRequest.error("Invalid bewit encoding")
  defp validate_bewit({:ok, bewit}, now, url) do
    case :string.split(bewit, "\\", :all) do
      values when length(values) != 4                            -> BadRequest.error("Invalid bewit structure")

      [id, exp, mac | _] when id == "" or exp == "" or mac == "" -> BadRequest.error("Missing bewit attributes")

      [_id, exp | _] = values                                    ->
      case :erlang.binary_to_integer(exp, 10) * 1000 <= now do
        true  -> Unauthorized.error("Access expired")

        false -> [[:id, :exp, :mac, :ext] |> Enum.zip(values) |> Enum.into(%{}), url]
      end
    end
  end

  @doc """
  *  options are the same as authenticate() with the exception that the only supported options are:
  * 'nonceFunc', 'timestampSkewSec', 'localtimeOffsetMsec'
  """
  @spec authenticate_message(binary(), integer(), binary(), map(), Hawk.credentials_fn(), Enumerable.t()) :: map() | {:error, term()}
  def authenticate_message(host, port, message, authorization, credentials_fn, options \\ %{})
  def authenticate_message(host, port, message, authorization, credentials_fn, options) when is_list(options) do
    authenticate_message(host, port, message, authorization, credentials_fn, Map.new(options))
  end
  def authenticate_message(host, port, message, %{id: id, ts: ts, nonce: nonce, hash: hash, mac: mac} = authorization, credentials_fn, options) do
    options = Map.merge(%{timestamp_skew_sec: 60}, options)
    now = Now.msec(options)
    artifacts = %{ts: ts, nonce: nonce, host: host, port: port, hash: hash}
    credentials = fetch_credentials(id, credentials_fn)

    ## Validate
    calculate_mac(artifacts, credentials, mac, "message")
    check_payload(authorization, credentials, %{payload: message})
    check_nonce(authorization, credentials, options)
    check_timestamp_staleness(authorization, credentials, now, options)

    %{artifacts: %{ts: ts, nonce: nonce, host: host, port: port, hash: hash}, credentials: credentials}
  end
  def authenticate_message(_host, _port, _message, _authorization, _credentials_fn, _options), do: BadRequest.error("Invalid authorization")

  defp fetch_credentials(id, credentials_fn) do
    try do
      credentials_fn.(id)
    else
      %{algorithm: algorithm} when algorithm not in @algorithms -> Unauthorized.error("Unknown algorithm")

      %{algorithm: _algorithm, key: _key} = credentials         -> credentials

      %{} = _credentials                                        -> InternalServerError.error("Invalid credentials")


      _                                                         -> Unauthorized.error("Unknown credentials")
    end
  end

  defp calculate_mac(artifacts, credentials, mac, type) do
    type
    |> Crypto.calculate_mac(credentials, artifacts)
    |> Kryptiles.fixed_time_comparison(mac)
    |> case do
         false -> Unauthorized.error("Bad mac")

         true  -> :ok
        end
  end

  defp check_payload(%{hash: hash}, %{algorithm: algorithm}, %{payload: payload}) do
    algorithm
    |> Crypto.calculate_payload_hash(payload, "")
    |> Kryptiles.fixed_time_comparison(hash)
    |> case do
         false -> Unauthorized.error("Bad payload hash")

         true  -> :ok
        end
  end
  defp check_payload(_artifacts, _credentials, %{payload: _}), do: Unauthorized.error("Missing required payload hash")
  defp check_payload(%{hash: _hash}, _credentials, _options), do: :ok
  defp check_payload(_artifacts, _credentials, _options), do: :ok

  defp check_nonce(%{nonce: nonce, ts: ts}, %{key: key}, %{nonce_fn: nounce_fn}) do
    try do
      nounce_fn.(key, nonce, ts)
    rescue
      _error      -> Unauthorized.error("Invalid nonce")
    else
      :ok         -> :ok

      _           -> Unauthorized.error("Invalid nonce")
    end
  end
  defp check_nonce(_artifacts, _credentials, _options), do: :ok

  defp check_timestamp_staleness(%{ts: ts}, credentials, now, %{timestamp_skew_sec: timestamp_skew_sec} = options) do
    ts = if is_binary(ts), do: :erlang.binary_to_integer(ts), else: ts
    case Kernel.abs((ts * 1000) - now) > (timestamp_skew_sec * 1000) do
      true  -> Unauthorized.error("Stale timestamp", Crypto.timestamp_message(credentials, options))

      false -> :ok
    end
  end
end
