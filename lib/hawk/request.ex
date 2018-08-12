defmodule Hawk.Request do
  @moduledoc false

  alias Plug.Conn

  @doc false
  @spec new(Conn.t(), keyword() | map()) :: Hawk.request() | {:error, term()}
  def new(conn, options \\ %{})
  def new(conn, options) when is_list(options), do: new(conn, Map.new(options))
  def new(%Conn{method: method, req_headers: req_headers} = conn, options) do
    case parse_host(conn, options) do
      {:error, reason} -> {:error, reason}

      {:ok, result}    ->
        Map.merge(%{method: method, url: resource(conn), authorization: get_req_header(req_headers, "authorization"), content_type: get_req_header(req_headers, "content-type")}, result)
    end
  end

  @doc false
  @spec resource(Conn.t() | URI.t() | map()) :: binary()
  def resource(%Conn{request_path: path, query_string: ""}), do: path
  def resource(%Conn{request_path: path, query_string: nil}), do: path
  def resource(%Conn{request_path: path, query_string: query}), do: __resource__(path, query)
  def resource(%URI{path: nil, query: nil}), do: "/"
  def resource(%URI{path: path, query: nil}), do: path
  def resource(%URI{path: path, query: query}), do: __resource__(path, query)
  defp __resource__(path, query), do: <<path::binary(), ??, query::binary()>>

  defp get_req_header(headers, header), do: for {key, value} <- headers, key == header, into: <<>>, do: value

  @doc false
  @spec parse_host(map(), map()) :: {:ok, map()} | {:error, term()}
  def parse_host(_conn, %{host: host, port: port}), do: {:ok, %{host: host, port: port}}
  def parse_host(%{req_headers: req_headers, host: host, port: port}, options) do
    case get_req_header(req_headers, String.downcase(options[:host_header_name] || "host")) do
      ""                                    -> {:ok, %{host: options[:host] || host, port: options[:port] || port}}

      header when byte_size(header) > 4096   -> {:error, {500, "Invalid host header"}}

      header                                 ->
        case Regex.run(~r/^(?:(?:\r\n)?\s)*((?:[^:]+)|(?:\[[^\]]+\]))(?::(\d+))?(?:(?:\r\n)?\s)*$/, header, capture: :all_but_first) do
          nil          -> {:error, {500, "Invalid host header"}}

          [host]       -> {:ok, %{host: options[:host] || host, port: options[:port] || port}}

          [host, port] -> {:ok, %{host: options[:host] || host, port: options[:port] || :erlang.binary_to_integer(port)}}
        end
    end
  end
end
