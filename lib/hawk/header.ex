defmodule Hawk.Header do
  @moduledoc false
  @attr ~w(app dlg error ext hash id mac nonce ts tsm)a

  alias Hawk.{BadRequest, InternalServerError, Unauthorized}


  @doc """
  Parse an `Authorization Header`

  # Examples

    iex> Hawk.Header.parse("Hawk id=\"asdasas3243223\", mac=\"asdsadas\"")
    %{"id" => "asdasas3243223"}

    iex> Hawk.Header.parse("Hawk id=\"asdasas3243223\" id=\"asdasas3243223\"")
    Hawk.BadRequest "Duplicate attribute"

    iex> Hawk.Header.parse("Scheme a=\"#{for _ <- 1..5000, into: <<>>, do: "x"}\"")
    Hawk.BadRequest "Header length too long"
  """
  @spec parse(binary() | charlist()) :: map() | no_return()
  def parse([]), do: Unauthorized.error("Hawk")
  def parse(header) when byte_size(header) > 4096, do: BadRequest.error("Header length too long")
  def parse(header) when length(header) > 4096, do:  BadRequest.error("Header length too long")
  def parse(<<h, a, w, k>>) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do:  BadRequest.error("Invalid header syntax")
  def parse([h, a, w, k]) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do:  BadRequest.error("Invalid header syntax")
  def parse(<<h, a, w, k, ?\s, attributes::binary()>>) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do: parse_attributes(attributes)
  def parse([h, a, w, k, ?\s | attributes]) when h in 'hH' and a in 'aA' and w in 'wW' and k in 'kK', do: parse_attributes(attributes)
  def parse(header) when is_binary(header) do
    case header =~ " " do
      false  -> BadRequest.error("Invalid header syntax")

      true   -> Unauthorized.error("Hawk")
    end
  end
  def parse(header) when is_list(header) do
    case :lists.member(?\s, header) do
      false  -> BadRequest.error("Invalid header syntax")

      true   -> Unauthorized.error("Hawk")
    end
  end
  def parse(_header), do: InternalServerError.error("Invalid host header")

  defp parse_attributes(binary, attributes \\ %{})
  for match <- @attr do
    list = :erlang.atom_to_list(match)
    key = :erlang.atom_to_binary(match, :utf8)
    defp parse_attributes(<<unquote(key), ?=, _rest::binary()>>, %{unquote(match) => _}), do: BadRequest.error("Duplicate attribute")
    defp parse_attributes(<<unquote(key), ?=, rest::binary()>>, attributes) do
      case parse_value(rest) do
        false         -> BadRequest.error("Bad attribute value")

        {value, <<>>} -> Map.put(attributes, unquote(match), value)

        {value, rest} -> parse_attributes(rest, Map.put(attributes, unquote(match), value))
      end
    end

    defp parse_attributes([unquote_splicing(list), ?= | _rest], %{unquote(match) => _}), do: BadRequest.error("Duplicate attribute")
    defp parse_attributes([unquote_splicing(list), ?= | rest], attributes) do
      case parse_value(rest) do
        false         -> BadRequest.error("Bad attribute value")

        {value, <<>>} -> Map.put(attributes, unquote(match), value)

        {value, rest} -> parse_attributes(rest, Map.put(attributes, unquote(match), value))
      end
    end
  end
  defp parse_attributes(<<_attribute::binary-size(1), ?=, _rest::binary()>>, _attributes), do: BadRequest.error("Unknown attribute")
  defp parse_attributes([_attribute, ?=  | _rest], _attributes), do: BadRequest.error("Unknown attribute")
  defp parse_attributes(_binary, _attributes), do: BadRequest.error("Invalid header syntax")

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
  defp parse_value(<<_::binary-size(1), _rest::binary()>>, _value), do: false
  defp parse_value([_ | _rest], _value), do: false

  @doc false
  @spec escape_attribute(binary()) :: binary()
  def escape_attribute(binary) do
    binary
    |> :binary.replace("\\", "\\\\")
    |> :binary.replace("\"", "\\\"")
  end
end
