defmodule Hawk.Unauthorized do
  @moduledoc false
  defexception [:plug_status, :message, :header]

  def error(msg, %{ts: ts, tsm: tsm}) do
    raise Hawk.Unauthorized, plug_status: 401,
                             message: msg,
                             header: "Hawk ts=\"#{ts}\", tsm=\"#{tsm}\", error=\"#{msg}\""
  end

  def error(msg) do
    raise Hawk.Unauthorized, plug_status: 401, message: msg, header: "Hawk error=\"#{msg}\""
  end

  def error() do
    raise Hawk.Unauthorized, plug_status: 401, message: "Unauthorized", header: "Hawk"
  end
end
defmodule Hawk.BadRequest do
  @moduledoc false
  defexception [:plug_status, :message]

  def error(msg) do
    raise Hawk.BadRequest, plug_status: 400, message: msg
  end
end
defmodule Hawk.InternalServerError do
  @moduledoc false
  defexception [:plug_status, :message]

  def error(msg) do
    raise Hawk.InternalServerError, plug_status: 500, message: msg
  end
end


