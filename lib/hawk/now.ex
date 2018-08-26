defmodule Hawk.Now do
  @moduledoc false

  @doc false
  @spec msec(Hawk.opts()) :: integer()
  def msec(options \\ []), do: SNTP.now() + (options[:localtime_offset_msec] || 0)

  @doc false
  @spec sec(Hawk.opts()) :: integer()
  def sec(options \\ []) do
    options
    |> msec()
    |> Kernel./(1000)
    |> :math.floor()
    |> Kernel.round()
  end
end
