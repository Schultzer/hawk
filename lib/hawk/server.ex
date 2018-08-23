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

  alias Hawk.{Crypto, Header, Now}
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
  @spec authenticate(Hawk.request(), function(), keyword() | map()) :: {:ok, %{artifacts: map(), credentials: map()}} | {:error, term()}
  def authenticate(request, credentials_fn, options \\ %{})
  def authenticate(request, credentials_fn, options) when is_list(options), do: authenticate(request, credentials_fn, Map.new(options))
  def authenticate(%{method: method, host: host, port: port, url: url} = req, credentials_fn, options) when is_function(credentials_fn) do
    options = Map.merge(%{timestamp_skew_sec: 60}, options)
    now = Now.msec(options)
    case Header.parse(req[:authorization]) do
      {:ok, %{id: id, ts: _, nonce: _, mac: mac} = attributes} ->
        artifacts = Map.merge(attributes, %{method: method, host: host, port: port, resource: url})
        case id |> credentials_fn.() |> validate_credentials() do
          {:error, reason}   -> {:error, reason}

          {:ok, credentials} ->
            {:ok, %{artifacts: artifacts, credentials: credentials}}
            |> validate_mac(mac, "header")
            |> check_payload(options)
            |> check_nonce(options)
            |> check_timestamp_staleness(now, options, fn -> Crypto.timestamp_message(credentials, options) end)
        end

      {:ok, _attributes} -> {:error, {400, "Missing attributes"}}

      {:error, reason}   -> {:error, reason}
    end
  end

  @doc """
  Authenticate a raw request payload hash - used when payload cannot be provided during `Hawk.Server.authenticate/3`
  the `credentials` and `artifacts` are received from `Hawk.Server.authenticate/3` the `content-type` is from the request

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate_payload(iodata(), map(), map(), iodata()) :: %{artifacts: map(), credentials: map()} | no_return()
  def authenticate_payload(payload, %{algorithm: algorithm} = credentials, %{hash: hash} = artifacts, content_type) do
    algorithm
    |> Crypto.calculate_payload_hash(payload, content_type)
    |> Kryptiles.fixed_time_comparison(hash)
    |> case do
         false -> {:error, {401, "Bad payload hash", Header.error("Bad payload hash")}}

         true  -> %{artifacts: artifacts, credentials: credentials}
       end
  end

  @doc """
  Authenticate payload hash - used when payload cannot be provided during `Hawk.Server.authenticate/3`
  takes the payload hash calculated using Hawk.Crypto.calculate_payload_hash/3 and  `artifacts` received from `Hawk.Server.authenticate/3`

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate_payload_hash(binary(), map()) :: {:ok, map()} | {:error, term()}
  def authenticate_payload_hash(calculate_hash, %{hash: hash} = artifacts) do
    case Kryptiles.fixed_time_comparison(calculate_hash, hash) do
      false -> {:error, {401, "Bad payload hash", Header.error("Bad payload hash")}}

      true  -> {:ok, %{artifacts: artifacts}}
    end
  end

  @doc false
  @spec header(map(), keyword() | map()) :: binary()
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
  @spec header(map(), map(), keyword() | map()) :: binary()
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
  defp maybe_add(%{hash: hash}, string),           do: <<string::binary(), ", hash=", ?", hash::binary(), ?">>
  defp maybe_add(%{ext: ext}, string),             do: <<string::binary(), ", ext=", ?", Header.escape_attribute(ext)::binary(), ?">>
  defp maybe_add(_, string),                       do: string

  @doc """
  Authenticate a Hawk bewit request

  ## Options
   * `:localtime_offset_msec` Local clock time offset express in a number of milliseconds (positive or negative). Defaults to 0.

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate_bewit(Hawk.request(), function(), keyword() | map()) :: {:ok, %{attributes: map(), credentials: map()}} | {:error, term()}
  def authenticate_bewit(request, credentials_fn, options \\ %{})
  def authenticate_bewit(request, credentials_fn, options) when is_list(options), do: authenticate_bewit(request, credentials_fn, Map.new(options))
  def authenticate_bewit(%{url: url}, _credentials_fn, _options) when byte_size(url) > 4096, do: {:error, {400, "Resource path exceeds max length"}}
  def authenticate_bewit(%{method: method}, _credentials_fn, _options) when method not in ["GET", "HEAD"], do: {:error, {401, "Invalid method", Header.error("Invalid method")}}
  def authenticate_bewit(%{authorization: authorization}, _credentials_fn, _options) when authorization !== [], do: {:error, {400, "Multiple authentications"}}
  def authenticate_bewit(req, credentials_fn, options) do
    options = Map.merge(%{timestamp_skew_sec: 60}, options)
    now = Now.msec(options)
    case parse(req[:url], now) do
      {:error, reason}    -> {:error, reason}

      {:ok, %{id: id, exp: exp, ext: ext, mac: mac} = bewit, url} ->
        case id |> credentials_fn.() |> validate_credentials() do
          {:error, reason}   -> {:error, reason}

          {:ok, credentials} ->
            {:ok, %{artifacts: %{ts: exp, nonce: "", method: "GET", resource: url, host: req[:host], port: req[:port], ext: ext}, credentials: credentials}}
            |> validate_mac(mac, "bewit")
            |> case do
                 {:ok, %{credentials: credentials}} -> {:ok, %{attributes: bewit, credentials: credentials}}

                 {:error, reason}                   -> {:error, reason}
               end
        end
    end
  end

  defp parse(binary, now, resource \\ <<>>)
  defp parse(<<>>, _now, _resource), do: {:error, {400, "Invalid bewit encoding"}}
  defp parse([], _now, _resource), do: {:error, {400, "Invalid bewit encoding"}}
  defp parse(<<_::binary-size(1), "bewit=">>, _now, _resource), do: {:error, {401, "Empty bewit", Header.error("Empty bewit")}}
  defp parse([_, ?b, ?e, ?w, ?i, ?t, ?=], _now, _resource), do: {:error, {401, "Empty bewit", Header.error("Empty bewit")}}
  defp parse(<<b::binary-size(1), "bewit=", bewit::binary()>>, now, resource) do
    resource = if b == "?", do: <<resource::binary(), b::binary()>>, else: resource
    bewit
    |> parse_bewit(resource)
    |> validate_bewit(now)
  end
  defp parse(<<b::binary-size(1), rest::binary()>>, now, resource) do
    parse(rest, now, <<resource::binary(), b::binary()>>)
  end
  defp parse(_binary, _now, _resource), do: {:error, {401, "Unauthorized", Header.error()}}

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
  defp validate_bewit(:error, _now, _url), do: {:error, {400, "Invalid bewit encoding"}}
  defp validate_bewit({:ok, bewit}, now, url) do
    case :string.split(bewit, "\\", :all) do
      values when length(values) != 4                            -> {:error, {400, "Invalid bewit structure"}}

      [id, exp, mac | _] when id == "" or exp == "" or mac == "" -> {:error, {400, "Missing bewit attributes"}}

      [_id, exp | _] = values                                    ->
      bewit = [:id, :exp, :mac, :ext] |> Enum.zip(values) |> Enum.into(%{})
      case :erlang.binary_to_integer(exp, 10) * 1000 <= now do
        true  -> {:error, {401, "Access expired", Header.error("Access expired")}}

        false -> {:ok, bewit, url}
      end
    end
  end

  @doc """
  Authenticate a message

  ## Options
   * `:localtime_offset_msec` Local clock time offset express in a number of milliseconds (positive or negative). Defaults to 0.
   * `:timestamp_skew_sec`. Defaults to 60.
   * `:nonce_fn` Local clock time offset express in a number of milliseconds (positive or negative). Defaults to 0.


  ## Examples

      iex> Hawk.Server.authenticate_message("https://exmaple.com", 4000, "my_message", authorization, credentials_fn)
      {:ok, map} | {:error, reason}
  """
  @spec authenticate_message(binary(), integer(), binary(), map(), function(), keyword() | map()) :: {:ok, map()} | {:error, term()}
  def authenticate_message(host, port, message, authorization, credentials_fn, options \\ %{})
  def authenticate_message(host, port, message, authorization, credentials_fn, options) when is_list(options) do
    authenticate_message(host, port, message, authorization, credentials_fn, Map.new(options))
  end
  def authenticate_message(host, port, message, %{id: id, ts: ts, nonce: nonce, hash: hash, mac: mac}, credentials_fn, options) when is_function(credentials_fn) do
    options = Map.merge(%{timestamp_skew_sec: 60}, options)
    now = Now.msec(options)

    %{artifacts: %{port: port, host: host, ts: ts, nonce: nonce, hash: hash}, credentials: credentials_fn.(id)}

    case id |> credentials_fn.() |> validate_credentials() do
      {:error, reason}   -> {:error, reason}

      {:ok, credentials} ->
        {:ok, %{artifacts: %{port: port, host: host, ts: ts, nonce: nonce, hash: hash}, credentials: credentials}}
        |> validate_mac(mac, "message")
        |> check_payload(%{payload: message}, "Bad message hash")
        |> check_nonce(options)
        |> check_timestamp_staleness(now, options)
        |> case do
             {:error, reason}                   -> {:error, reason}

             {:ok, %{credentials: credentials}} -> {:ok, %{credentials: credentials}}
           end
    end
  end
  def authenticate_message(_host, _port, _message, _authorization, _credentials_fn, _options), do: {:error, {400, "Invalid authorization"}}

  defp validate_credentials({:error, {status, msg, header}}), do: {:error, {status, msg, header}}
  defp validate_credentials({:ok, %{algorithm: algorithm, key: _key}} = result) when algorithm in @algorithms, do: result
  defp validate_credentials(%{algorithm: algorithm, key: _key} = result) when algorithm in @algorithms, do: {:ok, result}
  defp validate_credentials({:ok, %{algorithm: _,}}), do: {:error, {500, "Unknown algorithm"}}
  defp validate_credentials(%{algorithm: _,}), do: {:error, {500, "Unknown algorithm"}}
  defp validate_credentials({:ok, credentials}) when is_map(credentials), do: {:error, {500, "Invalid credentials"}}
  defp validate_credentials(credentials) when is_map(credentials), do: {:error, {500, "Invalid credentials"}}
  defp validate_credentials(_credentials), do: {:error, {401, "Unknown credentials", Header.error("Unknown credentials")}}

  def validate_mac({:error, reason}, _mac, _type), do: {:error, reason}
  def validate_mac({:ok, %{artifacts: artifacts, credentials: credentials}} = ok, mac, type) do
    type
    |> Crypto.calculate_mac(credentials, artifacts)
    |> Kryptiles.fixed_time_comparison(mac)
    |> case do
        false -> {:error, {401, "Bad mac", Header.error("Bad mac")}}

        true  -> ok
      end
  end

  defp check_payload(result, options, msg \\ "Bad payload hash")
  defp check_payload({:error, reason}, _options, _msg), do: {:error, reason}
  defp check_payload({:ok, %{artifacts: %{hash: hash}, credentials: %{algorithm: algorithm}}} = ok, %{payload: payload}, msg) do
    algorithm
    |> Crypto.calculate_payload_hash(payload, "")
    |> Kryptiles.fixed_time_comparison(hash)
    |> case do
         false -> {:error, {401, msg, Header.error(msg)}}

         true  -> ok
        end
  end
  defp check_payload({:ok, _}, %{payload: _}, _attributes), do: {:error, {401, "Missing required payload hash", Header.error("Missing required payload hash")}}
  defp check_payload({:ok, %{artifacts: %{hash: _hash}}} = ok, _options, _attributes), do: ok
  defp check_payload({:ok, _} = ok, _options, _attributes), do: ok

  defp check_nonce(result, options)
  defp check_nonce({:error, reason}, _options), do: {:error, reason}
  defp check_nonce({:ok, %{artifacts: %{nonce: nonce, ts: ts}, credentials: %{key: key}}} = ok, %{nonce_fn: nounce_fn}) when is_function(nounce_fn) do
    try do
      nounce_fn.(key, nonce, ts)
    rescue
      _error      -> {:error, {401, "Invalid nonce", Header.error("Invalid nonce")}}
    else
      :ok         -> ok

      _           -> {:error, {401, "Invalid nonce", Header.error("Invalid nonce")}}
    end
  end
  defp check_nonce({:ok, _} = ok, _options), do: ok

  defp check_timestamp_staleness(result, now, options, attributes \\ fn -> [] end)
  defp check_timestamp_staleness({:error, reason}, _now, _options, _attributes), do: {:error, reason}
  defp check_timestamp_staleness({:ok, %{artifacts: %{ts: ts}}} = ok, now, %{timestamp_skew_sec: timestamp_skew_sec}, attributes) do
    ts = if is_binary(ts), do: :erlang.binary_to_integer(ts), else: ts
    case Kernel.abs((ts * 1000) - now) > (timestamp_skew_sec * 1000) do
      true  -> {:error, {401, "Stale timestamp", Header.error("Stale timestamp", attributes.())}}

      false -> ok
    end
  end
end
