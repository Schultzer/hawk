defmodule Hawk.Request do
  @moduledoc false

  @type t :: %{method: binary(), url: binary(), host: binary(), port: pos_integer() | binary(), authorization: binary(), content_type: binary()}

  @doc false
  @spec new(map(), keyword() | map()) :: t() | {:error, {500, binary()}}
  def new(req, options \\ %{})
  def new(req, options) when is_list(options), do: new(req, Map.new(options))
  def new(%{method: method, req_headers: req_headers} = req, options) do
    case parse_host(req, options) do
      {:error, reason} -> {:error, reason}

      {:ok, result}    ->
        Map.merge(%{method: method, url: resource(req), authorization: get_req_header(req_headers, "authorization"), content_type: get_req_header(req_headers, "content-type")}, result)
    end
  end

  @doc false
  @spec resource(map()) :: binary()
  for {path, query} <- [{:request_path, :query_string}, {:path, :query}] do
    def resource(%{unquote(path) => nil, unquote(query) => nil}), do: "/"
    def resource(%{unquote(path) => path, unquote(query) => nil}), do: path
    def resource(%{unquote(path) => path, unquote(query) => ""}), do: path
    def resource(%{unquote(path) => path, unquote(query) => query}), do: <<path::binary(), ??, query::binary()>>
  end
  def resource(_), do: "/"

  defp get_req_header(headers, header), do: for {key, value} <- headers, key == header, into: <<>>, do: value

  @doc false
  @spec parse_host(map(), map()) :: {:ok, %{host: binary(), port: integer()}} | {:error, {500, binary()}}
  def parse_host(_req, %{host: host, port: port}), do: {:ok, %{host: host, port: port}}
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
