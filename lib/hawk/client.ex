defmodule Hawk.Client do
  @moduledoc """
  This module provides functions to create request headers and authenticate response

  ## Examples

      defmodule Myapp do
        def request_and_authenticate(uri \\\\ "example.com") do
          my_credentials  = %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}
          %{header: header, artifacts: artifacts} = Hawk.Client.header(uri, :get, my_credentials)


          case :httpc.request(:get, {[uri], [{'authorization', [header]}]}) do
            {:error, reason} ->
              {:error, reason}

            {:ok, {_status_line, headers, _body}}  ->
              Hawk.Client.authenticate(headers, my_credentials, artifacts)
          end
        end
      end
  """

  @typedoc false
  @type headers() :: [{binary() | charlist(), binary() | charlist()}]

  @typedoc false
  @type artifacts :: map()

  alias Hawk.{Crypto, Header, Request, Now, InternalServerError}

  @algorithms Crypto.algorithms()
  @methods ~w(delete get patch post put)a

  @doc """
  Generate an Authorization header for a given request, takes an uri `binary() | URI.t()`, `Hawk.Client.method()` and `Hawk.Client.credentials()`

  Options
    * `:ext` Application specific data sent via the ext attribute
    * `:ts` A pre-calculated timestamp in seconds
    * `:nonce` A pre-generated nonce
    * `:localtime_offset_msec` Time offset to sync with server time (ignored if timestamp provided)
    * `:payload` UTF-8 encoded string for body hash generation (ignored if hash provided)
    * `:content_type` Payload content-type (ignored if hash provided)
    * `:hash` Pre-calculated payload hash
    * `:app` Oz application id
    * `:dlg` Oz delegated-by application id


  ## Examples

      Hawk.Client.header("http://example.com/resource?a=b", :get, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"})
  """
  @spec header(binary() | URI.t(), Hawk.method(), Hawk.credentials(), Enumerable.t()) :: %{artifacts: artifacts(), header: binary()}
  def header(uri, method, credentials, options \\ %{})
  def header(uri, method, credentials, options) when is_list(options), do: header(uri, method, credentials, Map.new(options))
  def header(uri, method, %{algorithm: algorithm, id: _, key: _} = credentials, options) when is_binary(uri) and byte_size(uri) > 0 and algorithm in @algorithms and method in @methods do
    uri
    |> URI.parse()
    |> header(method, credentials, options)
  end
  def header(%URI{} = uri, method, %{algorithm: algorithm, id: _id, key: _key} = credentials, %{hash: _hash} = options) when algorithm in @algorithms and method in @methods do
    artifacts = create_artifacts(uri, method, options)
    %{artifacts: artifacts, header: create_header(artifacts, credentials)}
  end
  def header(%URI{} = uri, method, %{algorithm: algorithm, id: _id, key: _key} = credentials, %{payload: payload} = options) when algorithm in @algorithms and method in @methods do
    artifacts = uri |> create_artifacts(method, options) |> Map.put(:hash, Crypto.calculate_payload_hash(algorithm, "#{payload}", "#{options[:content_type]}"))
    %{artifacts: artifacts, header: create_header(artifacts, credentials)}
  end
  def header(%URI{} = uri, method, %{algorithm: algorithm, id: _id, key: _key} = credentials, options) when algorithm in @algorithms and method in @methods do
    artifacts = create_artifacts(uri, method, options)
    %{artifacts: artifacts, header: create_header(artifacts, credentials)}
  end

  defp create_artifacts(%URI{host: host, port: port} = uri, method, options) do
    %{ts: Now.sec(options), nonce: Kryptiles.random_string(6)}
    |> Map.merge(options)
    |> Map.merge(%{host: host, port: port, method: String.upcase("#{method}"), resource: Request.resource(uri)})
  end

  defp create_header(artifacts, %{id: id} = credentials) do
    artifacts
    |> Map.merge(%{id: id, mac: Crypto.calculate_mac("header", credentials, artifacts)})
    |> header_string()
  end

  defp header_string(map, pos \\ 0, acc \\ "Hawk")
  defp header_string(_rest, 8, acc), do: :erlang.iolist_to_binary(acc)
  for {key, [pos, sep]} <- [id: [0, " "], ts: [1, ", "], nonce: [2, ", "], hash: [3, ", "], ext: [4, ", "], mac: [5, ", "], app: [6, ", "], dlg: [7, ", "]] do
    defp header_string(%{unquote(key) =>  v} = rest, unquote(pos), acc) do
      header_string(rest, unquote(pos) + 1, [acc | "#{unquote(sep)}#{unquote(key)}=\"#{v}\""])
    end
  end
  defp header_string(rest, pos, acc), do: header_string(rest, pos + 1, acc)

  @doc """
  Validate a `:httpc` response

  ## Options
    * `:payload` optional payload received
    * `:required` specifies if a Server-Authorization header is required. Defaults to `false`

  ## Examples

      iex> Hawk.Client.authenticate(res, %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, artifacts)
  """
  @spec authenticate(headers(), Hawk.credentials(), artifacts(), Enumerable.t()) :: map() | no_return()
  def authenticate(headers, credentials, artifacts, options \\ %{})
  def authenticate(headers, credentials, artifacts, options) when is_list(options), do: authenticate(headers, credentials, artifacts, Map.new(options))
  def authenticate(headers, %{algorithm: algorithm, id: _id, key: _key} = credentials, artifacts, options) when algorithm in @algorithms and is_map(artifacts) and is_list(headers) do
    headers
    |> parse_headers()
    |> validate_headers(credentials, artifacts, options)
    |> Map.drop(["content-type"])
  end

  defp parse_headers(headers, header \\ %{})
  defp parse_headers([], headers), do: headers
  for header <- ['www-authenticate', "www-authenticate"] do
    defp parse_headers([{unquote(header), value} | rest], headers) do
      try do
        headers = Map.put(headers, "#{unquote(header)}", Header.parse(value))
        parse_headers(rest, headers)
      rescue
        _error -> Hawk.InternalServerError.error("Invalid WWW-Authenticate header")
      end
    end
  end
  for header <- ['server-authorization', "server-authorization"] do
    defp parse_headers([{unquote(header), value} | rest], headers) do
      try do
        headers = Map.put(headers, "#{unquote(header)}", Header.parse(value))
        parse_headers(rest, headers)
      rescue
        _error -> Hawk.InternalServerError.error("Invalid Server-Authorization header")
      end
    end
  end
  for header <- ['content-type', "content-type"] do
    defp parse_headers([{unquote(header), value} | rest], headers) do
      [header | _] = :string.split(value, ';')
      headers = Map.put(headers, "content-type", header)
      parse_headers(rest, headers)
    end
  end
  defp parse_headers([_ | rest], headers), do: parse_headers(rest, headers)

  defp validate_headers(%{"server-authorization" => _} = headers, %{algorithm: algorithm} = credentials, artifacts, options) do
    headers
    |> validate_timestamp(credentials)
    |> validate_mac(credentials, artifacts)
    |> validate_hash(algorithm, options)
  end
  defp validate_headers(headers, %{algorithm: _algorithm} = credentials, _artifacts, _options) do
    validate_timestamp(headers, credentials)
  end

  defp validate_timestamp(%{"www-authenticate" => %{ts: ts, tsm: tsm}} = headers, credentials) do
    case tsm !== Crypto.calculate_ts_mac(ts, credentials) do
      true  -> InternalServerError.error("Invalid server timestamp hash")

      false -> headers
    end
  end
  # defp validate_timestamp(%{"www-authenticate" => %{error: "Stale timestamp"}} = headers, _credentials) do
  #   InternalServerError.error("Invalid WWW-Authenticate header")
  # end
  # defp validate_timestamp(%{"www-authenticate" => %{error: error}} = headers, _credentials) do
  #   InternalServerError.error("Invalid WWW-Authenticate header")
  # end
  defp validate_timestamp(headers, _credentials),  do: headers

  defp validate_mac(%{"server-authorization" => %{ext: ext, hash: hash, mac: mac}} = headers, credentials, artifacts) do
    case mac !== Crypto.calculate_mac("response", credentials, %{artifacts | ext: ext, hash: hash}) do
      true  -> InternalServerError.error("Bad response mac")

      false -> headers
    end
  end
  defp validate_mac(headers, _credentials, _artifacts), do: headers

  defp validate_hash(headers, _algorithm, %{payload: ""}), do: headers
  defp validate_hash(%{"server-authorization" => %{hash: hash}} = headers, algorithm, %{payload: payload}) do
    case hash !== Crypto.calculate_payload_hash(algorithm, payload, headers["content-type"]) do
      true  -> InternalServerError.error("Bad response payload mac")

      false -> headers
    end
  end
  defp validate_hash(%{"server-authorization" => _}, _algorithm, %{payload: _payload}) do
    InternalServerError.error("Missing response hash attribute")
  end
  defp validate_hash(headers, _algorithm, _options), do: headers

  @doc """
  Generate a bewit value for a given URI
  takes 3 arguments `binary() | URI.t()`, `Hawk.Client.credentials()` and time to live in seconds

  ## Options
    * `:ext` Application specific data sent via the ext attribute
    * `:localtime_offset_msec` Time offset to sync with server time

  ## Examples
      iex> credentials = %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}
      iex> ttl = 60 * 60
      iex> options = %{ext: "application-specific", localtime_offset_msec: 400}
      iex> uri = URI.parse("http://example.com/resource?a=b")

      iex> Hawk.Client.get_bewit("http://example.com/resource?a=b", credentials, ttl)

      iex> Hawk.Client.get_bewit(uri, credentials, ttl)
  """
  @spec get_bewit(binary() | URI.t(), Hawk.credentials(), integer(), Enumerable.t()) :: %{artifacts: artifacts(), bewit: binary()}
  def get_bewit(uri, credentials, ttl, options \\ %{})
  def get_bewit(uri, credentials, ttl, options) when is_list(options), do: get_bewit(uri, credentials, ttl, Map.new(options))
  def get_bewit(uri, %{algorithm: algorithm, id: _, key: _} = credentials, ttl, options) when is_binary(uri) and byte_size(uri) > 0 and is_integer(ttl) and algorithm in @algorithms do
    uri
    |> URI.parse()
    |> get_bewit(credentials, ttl, options)
  end
  def get_bewit(%URI{host: host, port: port} = uri, %{algorithm: algorithm, id: id, key: _} = credentials, ttl, options) when is_integer(ttl) and algorithm in @algorithms do
    exp = options |> Now.sec() |> :math.floor() |> Kernel.+(ttl) |> Kernel.round()
    artifacts = Map.merge(%{ts: exp, nounce: "", method: "GET", resource: Request.resource(uri), host: host, port: port}, Map.take(options, [:ext]))
    mac = Crypto.calculate_mac("bewit", credentials, artifacts)
    %{artifacts: artifacts, bewit: Base.url_encode64("#{id}\\#{exp}\\#{mac}\\#{options[:ext]}", padding: false)}
  end

  @doc """
  Generate an authorization string for a UTF-8 encoded string for body hash generation

  ## Options
    * `:timestamp` A pre-calculated timestamp in seconds
    * `:nonce` A pre-generated nonce
    * `:localtime_offset_msec` Time offset to sync with server time (ignored if timestamp provided)

  ## Examples
      iex> Hawk.Client.message("example.com", 8000, "{\\"some\\":\\"payload\\"}", %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, hash: "osPwIDqS9cUeJnQRQEdq8upF/tGVVyo6KFgUiUoDoLs=", timestamp: 1531684204, nonce: "x0AIzk")
      %{hash: "osPwIDqS9cUeJnQRQEdq8upF/tGVVyo6KFgUiUoDoLs=", id: "dh37fgj492je", mac: "Yb4eQ2MXJAc4MFvyouOOGhLKE9Ys/PqdYYub6gYwgrI=", nonce: "x0AIzk", ts: 1531684204}
  """
  @spec message(binary(), 0..65535, binary(), Hawk.credentials(), Enumerable.t()) :: %{hash: binary(), id: binary(), mac: binary(), host: binary(), port: 0..65535, nonce: binary(), ts: integer()}
  def message(host, port, message, credentials, options \\ %{})
  def message(host, port, message, credentials, options) when is_list(options), do: message(host, port, message, credentials, Map.new(options))
  def message(host, port, message, %{algorithm: algorithm, id: id, key: _} = credentials, options) when is_binary(host) and byte_size(host) > 0 and is_binary(message) and port in 0..65535 and algorithm in @algorithms do
    artifacts = %{ts: options[:timestamp] || Now.sec(options), nonce: options[:nonce] || Kryptiles.random_string(6), host: host, port: port, hash: Crypto.calculate_payload_hash(algorithm, message, "")}
    Map.merge(artifacts, %{id: id, mac: Crypto.calculate_mac("message", credentials, artifacts)})
  end
end
