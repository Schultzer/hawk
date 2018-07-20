defmodule Hawk.Now do
  @moduledoc false

  @doc false
  @spec msec(Enumerable.t()) :: integer()
  def msec(options \\ [])
  def msec(options), do: SNTP.now() + (options[:localtime_offset_msec] || 0)

  @spec sec(Enumerable.t()) :: integer()
  def sec(options \\ [])
  def sec(options) do
    options
    |> msec()
    |> Kernel./(1000)
    |> :math.floor()
    |> Kernel.round()
  end
end
