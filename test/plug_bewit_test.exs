defmodule PlugBewitTest do
  use ExUnit.Case
  use Plug.Test

  setup do
    Application.put_env(:plug, :validate_header_keys_during_test, true)
    [conn: conn(:get, "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQa"), credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"} end]
  end

  describe "call/2" do
    test "should fail on invalid host header", %{conn: conn,credentials_fn: credentials_fn} do
      conn = conn
             |> put_req_header("host", "example.com:something")
             |> Plug.Hawk.call(credentials_fn: credentials_fn)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {500, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid host header"} == sent_resp(conn)
    end
  end
end
