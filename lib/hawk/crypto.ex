defmodule Hawk.Crypto do
  @moduledoc false

  @doc false
  @spec header_version() :: pos_integer()
  def header_version(), do: 1

  @doc false
  @spec algorithms() :: [Hawk.algorithm(), ...]
  def algorithms(), do: ~w(sha sha256)a ++ ~w(sha sha256)c ++ ~w(sha sha256)s

  @doc """
  Calculate the request MAC

  ### Options
   * `:method` HTTP verb
   * `:resource` Resource
   * `:host` Host
   * `:port` Port
   * `:ts` A pre-calculated timestamp in seconds
   * `:nonce` A pre-generated nonce
   * `:hash` Pre-calculated payload hash
   * `:ext` Application specific data sent via the ext attribute
   * `:app` Application id (Oz)
   * `:dlg` Delegated by application id (Oz), requires `:app`

  ## Example

      iex> Hawk.Crypto.calculate_mac("response", %{algorithm: :sha256, key: "aoijedoaijsdlaksjdl"}, %{method: "GET", resource: "/resource?a=1&b=2", host: "example.com", port: 8080, ts: 1357718381034, nonce: "d3d345f", hash: "U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=", ext: "app-specific-data", app: "hf48hd83qwkj", dlg: "d8djwekds9cj"})
      "bhFj6x2GixVKlUb9/0/yoF0vMMNQscmHMX8N8Al4xVc"
  """
  @spec calculate_mac(iodata(), map(), keyword() | map()) :: binary()
  def calculate_mac(type, credentials, options) when is_list(options), do: calculate_mac(type, credentials, Map.new(options))
  def calculate_mac(type, %{algorithm: algorithm, key: key}, options) do
    normalized = generate_normalized_string(type, options)

    algorithm
    |> to_atom()
    |> :crypto.hmac(key, normalized)
    |> Base.encode64()
  end

  @doc false
  @spec generate_normalized_string(iodata(), keyword() | map()) :: binary()
  def generate_normalized_string(type, options) do
    resource = "#{options[:resource]}" |> URI.parse() |> Hawk.Request.resource()

    maybe_add("""
    hawk.#{header_version()}.#{type}
    #{options[:ts]}
    #{options[:nonce]}
    #{String.upcase("#{options[:method]}")}
    #{resource}
    #{String.downcase("#{options[:host]}")}
    #{options[:port]}
    #{(options[:hash])}
    """, options)
  end

  defp maybe_add(string, %{ext: ext, app: app, dlg: dlg}), do: <<string::binary(), "#{nomarlize_ext(ext)}", ?\n, app::binary(), ?\n, dlg::binary(), ?\n>>
  defp maybe_add(string, %{app: app, dlg: dlg}), do: <<?\n, string::binary(), app::binary(), ?\n, dlg::binary(), ?\n>>
  defp maybe_add(string, %{ext: ext}), do: <<string::binary(), "#{nomarlize_ext(ext)}", ?\n>>
  defp maybe_add(string, _), do: <<string::binary(), ?\n>>

  defp nomarlize_ext(ext), do: :string.replace(ext, "\\", "\\\\", :all) |> :string.replace("\n", "\\n", :all)

  @doc false
  @spec calculate_payload_hash(Hawk.algorithm(), iodata(), iodata()) :: binary()
  def calculate_payload_hash(algorithm, payload, content_type) do
    algorithm
    |> to_atom()
    |> :crypto.hash_init()
    |> :crypto.hash_update("hawk.#{header_version()}.payload\n")
    |> :crypto.hash_update("#{content_type}\n")
    |> :crypto.hash_update(payload)
    |> :crypto.hash_update("\n")
    |> :crypto.hash_final()
    |> Base.encode64()
  end

  @doc false
  @spec timestamp_message(map(), Enumerable.t()) :: %{ts: integer(), tsm: binary()}
  def timestamp_message(credentials, options) do
    now = Hawk.Now.sec(options)
    tsm = calculate_ts_mac(now, credentials)
    %{ts: now, tsm: tsm}
  end

  @doc false
  @spec calculate_ts_mac(integer() | binary(), map()) :: binary()
  def calculate_ts_mac(ts, %{algorithm: algorithm, key: key}) do
    algorithm
    |> to_atom()
    |> :crypto.hmac(key, "hawk.#{header_version()}.ts\n#{ts}\n")
    |> Base.encode64()
  end

  @doc false
  @spec to_atom(Hawk.algorithm()) :: atom()
  def to_atom(algorithm) when is_binary(algorithm), do: :erlang.binary_to_atom(algorithm, :utf8)
  def to_atom(algorithm) when is_list(algorithm),   do: :erlang.list_to_atom(algorithm)
  def to_atom(algorithm) when is_atom(algorithm),   do: algorithm
end
