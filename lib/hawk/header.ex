defmodule Hawk.Header do
  @moduledoc false
  @attr ~w(app dlg error ext hash id mac nonce ts tsm)a

  # alias Hawk.{BadRequest, InternalServerError, Unauthorized}


  @doc """
  Parse an `Authorization Header`

  # Examples

    iex> Hawk.Header.parse("Hawk id=\"asdasas3243223\", mac=\"asdsadas\"")
    {:ok, %{"id" => "asdasas3243223"}}

    iex> Hawk.Header.parse("Hawk id=\"asdasas3243223\", id=\"asdasas3243223\"")
    {:error, {400, "Duplicate attribute: id"}}

    iex> Hawk.Header.parse("Scheme a=\"#{for _ <- 1..5000, into: <<>>, do: "x"}\"")
    {:error, {400, "Header length too long"}}
  """
  @spec parse(binary() | charlist()) :: {:ok, map()} | {:error, term()}
  def parse([]), do: {:error, {401, "Unauthorized", __MODULE__.error()}}
  def parse(header) when byte_size(header) > 4096, do: {:error, {400, "Header length too long"}}
  def parse(header) when length(header) > 4096, do: {:error, {400, "Header length too long"}}
  def parse(<<h, a, w, k>>) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do: {:error, {400, "Invalid header syntax"}}
  def parse([h, a, w, k]) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do: {:error, {400, "Invalid header syntax"}}
  def parse(<<h, a, w, k, ?\s, attributes::binary()>>) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do: parse_attributes(attributes)
  def parse([h, a, w, k, ?\s | attributes]) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do: parse_attributes(attributes)
  def parse(header) when is_binary(header) do
    case header =~ " " do
      false  -> {:error, {400, "Invalid header syntax"}}

      true   -> {:error, {401, "Unauthorized", __MODULE__.error()}}
    end
  end
  def parse(header) when is_list(header) do
    case :lists.member(?\s, header) do
      false  -> {:error, {400, "Invalid header syntax"}}

      true   -> {:error, {401, "Unauthorized", __MODULE__.error()}}
    end
  end
  def parse(_header), do: {:error, {500, "Invalid host header"}}

  defp parse_attributes(binary, attributes \\ %{})
  for match <- @attr do
    list = :erlang.atom_to_list(match)
    key = :erlang.atom_to_binary(match, :utf8)
    defp parse_attributes(<<unquote(key), ?=, _rest::binary()>>, %{unquote(match) => _}), do: {:error, {400, "Duplicate attribute: #{unquote(match)}"}}
    defp parse_attributes(<<unquote(key), ?=, rest::binary()>>, attributes) do
      case parse_value(rest) do
        {:error, value}  -> {:error, {400, "Bad attribute value: #{value}"}}

        {value, <<>>}    -> {:ok, Map.put(attributes, unquote(match), value)}

        {value, rest}    -> parse_attributes(rest, Map.put(attributes, unquote(match), value))
      end
    end

    defp parse_attributes([unquote_splicing(list), ?= | _rest], %{unquote(match) => _}), do: {:error, {400, "Duplicate attribute: #{unquote(match)}"}}
    defp parse_attributes([unquote_splicing(list), ?= | rest], attributes) do
      case parse_value(rest) do
        {:error, value}  -> {:error, {400, "Bad attribute value: #{value}"}}

        {value, <<>>}    -> {:ok, Map.put(attributes, unquote(match), value)}

        {value, rest}    -> parse_attributes(rest, Map.put(attributes, unquote(match), value))
      end
    end
  end
  defp parse_attributes(<<attribute::binary-size(1), ?=, _rest::binary()>>, _attributes), do: {:error, {400, "Unknown attribute: #{attribute}"}}
  defp parse_attributes([attribute, ?=  | _rest], _attributes), do: {:error, {400, "Unknown attribute: #{attribute}"}}
  defp parse_attributes(_binary, _attributes), do: {:error, {400, "Bad header format"}}

  defp parse_value(binary, value \\ <<>>)
  defp parse_value(<<?">>, value), do: {value, <<>>}
  defp parse_value([?"], value), do: {value, <<>>}
  defp parse_value(<<?", rest::binary>>, <<>> = value), do: parse_value(rest, value)
  defp parse_value([?" | rest], <<>> = value), do: parse_value(rest, value)
  defp parse_value(<<?", ?,, ?\s, rest::binary()>>, value), do: {value, rest}
  defp parse_value([?", ?,, ?\s | rest], value), do: {value, rest}

  for v <- '!#$%&\'()*+,-./:;<=>?@[]^_`{|}~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ' do
    defp parse_value(<<unquote(v), rest::binary()>>, value) do
      parse_value(rest, <<value::binary(), unquote(v)>>)
    end
    defp parse_value([unquote(v) | rest], value) do
      parse_value(rest, <<value::binary(), unquote(v)>>)
    end
  end
  defp parse_value(<<value::binary-size(1), _rest::binary()>>, _value), do: {:error, value}
  defp parse_value([value | _rest], _value), do: {:error, value}

  @doc false
  @spec escape_attribute(binary()) :: binary()
  def escape_attribute(binary) do
    binary
    |> :binary.replace("\\", "\\\\")
    |> :binary.replace("\"", "\\\"")
  end

  @doc !"""
  Generate a `WWW-Authenticate` header

  # Examples

    iex> Hawk.Header.error()
    {"www-authenticate", "Hawk"}

    iex> Hawk.Header.error("Stale timestamp")
    {"www-authenticate", "Hawk error=\"Stale timestamp\""}

    iex> Hawk.Header.error("Stale timestamp", %{ts: 121521521414, tsm: "asfaijfoiffas"})
    {"www-authenticate", "Hawk ts=\"121521521414\", tsm=\"asfaijfoiffas\", error=\"Stale timestamp\""}
  """
  @spec error(binary(), map() | keyword()) :: {binary(), binary()}
  def error(msg \\ "", attr \\ [])
  def error("", attr) do
    {"www-authenticate", base(attr)}
  end
  def error(msg, attr) do
    {"www-authenticate", <<base(attr)::binary(), " error=", ?", msg::binary(), ?">>}
  end

  defp base(attr), do: for {key, value} <- attr, into: <<"Hawk">>, do: " #{key}=\"#{value}\","
end
