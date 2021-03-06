defmodule Hawk.Client do
  @moduledoc """
  This module provides functions to create request headers and authenticate response.

  ## Examples

      defmodule Myapp.Hawk do
        def request_and_authenticate(uri, credentials) do
          result = Hawk.Client.header(uri, :get, credentials)

          case :httpc.request(:get, {[uri], [{'authorization', [result.header]}]}) do
            {:error, reason} ->
              {:error, reason}

            {:ok, {_status_line, headers, _body}}  ->
              Hawk.Client.authenticate(headers, result)
          end
        end
      end
  """

  @typedoc false
  @type headers() :: [{binary() | charlist(), binary() | charlist()}]

  alias Hawk.{Crypto, Header, Request, Now}

  @algorithms Crypto.algorithms()
  @methods ~w(delete get patch post put)a

  @doc """
  Generate an Authorization header for a given request.

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
  """
  @spec header(binary() | URI.t(), :delete | :get | :patch | :post | :put, map(), Hawk.opts()) :: %{artifacts: map(), credentials: map(), header: binary()}
  def header(uri, method, credentials, options \\ %{})
  def header(uri, method, credentials, options) when is_list(options), do: header(uri, method, credentials, Map.new(options))
  def header(uri, method, %{algorithm: algorithm, id: _, key: _} = credentials, options) when is_binary(uri) and byte_size(uri) > 0 and algorithm in @algorithms and method in @methods do
    uri
    |> URI.parse()
    |> header(method, credentials, options)
  end
  def header(%URI{} = uri, method, %{algorithm: algorithm, id: _id, key: _key} = credentials, %{hash: _hash} = options) when algorithm in @algorithms and method in @methods do
    artifacts = create_artifacts(uri, method, options)
    %{artifacts: artifacts, credentials: credentials, header: create_header(artifacts, credentials)}
  end
  def header(%URI{} = uri, method, %{algorithm: algorithm, id: _id, key: _key} = credentials, %{payload: payload} = options) when algorithm in @algorithms and method in @methods do
    artifacts = uri |> create_artifacts(method, options) |> Map.put(:hash, Crypto.calculate_payload_hash(algorithm, "#{payload}", "#{options[:content_type]}"))
    %{artifacts: artifacts, credentials: credentials, header: create_header(artifacts, credentials)}
  end
  def header(%URI{} = uri, method, %{algorithm: algorithm, id: _id, key: _key} = credentials, options) when algorithm in @algorithms and method in @methods do
    artifacts = create_artifacts(uri, method, options)
    %{artifacts: artifacts, credentials: credentials, header: create_header(artifacts, credentials)}
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
  Authenticate response `headers`

  ## Options
    * `:payload` optional payload received
    * `:required` specifies if a Server-Authorization header is required. Defaults to `false`
  """
  @spec authenticate(headers(), map(), Hawk.opts()) :: {:ok, map()} | {:error, {integer(), binary()}}
  def authenticate(headers, result, options \\ %{})
  def authenticate(headers, result, options) when is_list(options), do: authenticate(headers, result, Map.new(options))
  def authenticate(headers, %{credentials: %{algorithm: algorithm, id: _id, key: _key} = credentials, artifacts: artifacts}, options) when algorithm in @algorithms and is_map(artifacts) and is_list(headers) do
    headers
    |> parse_headers()
    |> validate_headers(credentials, artifacts, options)
    |> case do
       {:error, reason} -> {:error, reason}

       {:ok, headers}   -> {:ok, Map.drop(headers, ["content-type"])}
    end
  end

  defp parse_headers(headers, header \\ %{})
  defp parse_headers(_headers, {:error, reason}), do: {:error, reason}
  defp parse_headers([], headers), do: headers
  for header <- ['www-authenticate', "www-authenticate"] do
    defp parse_headers([{unquote(header), value} | rest], headers) do
      case Header.parse(value) do
        {:ok, result}     -> parse_headers(rest, Map.put(headers, "#{unquote(header)}", result))

        {:error, _reason} -> parse_headers(rest, {:error, {500, "Invalid WWW-Authenticate header"}})
      end
    end
  end
  for header <- ['server-authorization', "server-authorization"] do
    defp parse_headers([{unquote(header), value} | rest], headers) do
      case Header.parse(value) do
        {:ok, result}    -> parse_headers(rest, Map.put(headers, "#{unquote(header)}", result))

        {:error, _reason} -> parse_headers(rest, {:error, {500, "Invalid Server-Authorization header"}})
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

  defp validate_headers({:error, reason}, _credentials, _artifacts, _options), do: {:error, reason}
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
      true  -> {:error, {500, "Invalid server timestamp hash"}}

      false -> {:ok, headers}
    end
  end
  # defp validate_timestamp(%{"www-authenticate" => %{error: "Stale timestamp"}} = headers, _credentials) do
  #   InternalServerError.error("Invalid WWW-Authenticate header")
  # end
  # defp validate_timestamp(%{"www-authenticate" => %{error: error}} = headers, _credentials) do
  #   InternalServerError.error("Invalid WWW-Authenticate header")
  # end
  defp validate_timestamp(headers, _credentials),  do: {:ok, headers}

  defp validate_mac({:error, reason}, _credentials, _artifacts), do: {:error, reason}
  defp validate_mac({:ok, %{"server-authorization" => %{ext: ext, hash: hash, mac: mac}}} = headers, credentials, artifacts) do
    case mac !== Crypto.calculate_mac("response", credentials, %{artifacts | ext: ext, hash: hash}) do
      true  -> {:error, {500, "Bad response mac"}}

      false -> headers
    end
  end
  defp validate_mac(headers, _credentials, _artifacts), do: headers

  defp validate_hash({:error, reason}, _algorithm, _options), do: {:error, reason}
  defp validate_hash(headers, _algorithm, %{payload: ""}), do: headers
  defp validate_hash({:ok, %{"server-authorization" => %{hash: hash}} = headers} = ok, algorithm, %{payload: payload}) do
    case hash !== Crypto.calculate_payload_hash(algorithm, payload, headers["content-type"]) do
      true  -> {:error, {500, "Bad response payload mac"}}

      false -> ok
    end
  end
  defp validate_hash({:ok, %{"server-authorization" => _}}, _algorithm, %{payload: _payload}) do
    {:error, {500, "Missing response hash attribute"}}
  end
  defp validate_hash(headers, _algorithm, _options), do: headers

  @doc """
  Generate a bewit value for a given URI.

  ## Options
    * `:ext` Application specific data sent via the ext attribute
    * `:localtime_offset_msec` Time offset to sync with server time

  ## Examples
      iex> Hawk.Client.get_bewit("http://example.com/resource?a=b", %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}, 3600, ext: "application-specific", localtime_offset_msec: 400)
      %{
        artifacts: %{
          ext: "application-specific",
          host: "example.com",
          method: "GET",
          nounce: "",
          port: 80,
          resource: "/resource?a=b",
          ts: 1535315623
        },
        bewit: "ZGgzN2ZnajQ5MmplXDE1MzUzMTU2MjNcZE9laXcxL1Z4SjVSeVFKOXFJT0l1cFhVQ3VwTzZiMG5OeDBRMWROOXZVcz1cYXBwbGljYXRpb24tc3BlY2lmaWM"
      }
  """
  @spec get_bewit(binary() | URI.t(), map(), integer(), Hawk.opts()) :: %{artifacts: map(), bewit: binary()}
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
  @spec message(binary(), 0..65535, binary(), map(), Hawk.opts()) :: %{hash: binary(), id: binary(), mac: binary(), host: binary(), port: 0..65535, nonce: binary(), ts: integer()}
  def message(host, port, message, credentials, options \\ %{})
  def message(host, port, message, credentials, options) when is_list(options), do: message(host, port, message, credentials, Map.new(options))
  def message(host, port, message, %{algorithm: algorithm, id: id, key: _} = credentials, options) when is_binary(host) and byte_size(host) > 0 and is_binary(message) and port in 0..65535 and algorithm in @algorithms do
    artifacts = %{ts: options[:timestamp] || Now.sec(options), nonce: options[:nonce] || Kryptiles.random_string(6), host: host, port: port, hash: Crypto.calculate_payload_hash(algorithm, message, "")}
    Map.merge(artifacts, %{id: id, mac: Crypto.calculate_mac("message", credentials, artifacts)})
  end
end
