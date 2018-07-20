defmodule Hawk.Request do
  @moduledoc false

  alias Plug.Conn
  alias Hawk.InternalServerError

  @doc false
  @spec new(Conn.t(), Enumerable.t()) :: Hawk.request() | {:error, binary()}
  def new(conn, options \\ %{})
  def new(conn, options) when is_list(options), do: new(conn, Map.new(options))
  def new(%Conn{method: method} = conn, options) do
    Map.merge(%{method: method, url: resource(conn), authorization: get_req_header(conn, "authorization"), content_type: get_req_header(conn, "content-type")}, parse_host(conn, options))
  end

  def resource(%Conn{request_path: path, query_string: ""}), do: path
  def resource(%Conn{request_path: path, query_string: nil}), do: path
  def resource(%Conn{request_path: path, query_string: query}), do: __resource__(path, query)
  def resource(%URI{path: path, query: nil}), do: path
  def resource(%URI{path: path, query: query}), do: __resource__(path, query)
  defp __resource__(path, query), do: <<path::binary(), ??, query::binary()>>

  defp get_req_header(conn, header) do
    conn
    |> Conn.get_req_header(header)
    |> List.first()
  end

  def parse_host(_conn, %{host: host, port: port}), do: %{host: host, port: port}
  def parse_host(conn, options) do
    host = options[:host_header_name] || "host"
    case get_req_header(conn, String.downcase(host)) do
      nil                                    -> %{host: options[:host] || conn.host, port: options[:port] || conn.port}

      header when byte_size(header) > 4096   -> InternalServerError.error("Invalid host header")

      header                                 ->
        case Regex.run(~r/^(?:(?:\r\n)?\s)*((?:[^:]+)|(?:\[[^\]]+\]))(?::(\d+))?(?:(?:\r\n)?\s)*$/, header, capture: :all_but_first) do
          nil          -> InternalServerError.error("Invalid host header")

          [host]       -> %{host: options[:host] || host, port: options[:port] || conn.port}

          [host, port] -> %{host: options[:host] || host, port: options[:port] || :erlang.binary_to_integer(port)}
        end
    end
  end
end
