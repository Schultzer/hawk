defmodule PlugHawkTest do
  use ExUnit.Case
  alias Hawk.Now
  use Plug.Test

  setup do
    Application.put_env(:plug, :validate_header_keys_during_test, true)
    [conn: conn(:get, "/resource/4?filter=a"), credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"} end]
  end

  describe "call/2" do
    test "parses a valid authentication header (host override)", %{conn: conn, credentials_fn: credentials_fn} do
      conn = conn
             |> put_req_header("host", "example1.com:8080")
             |> put_req_header("authorization", "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\"")
             |> Plug.Hawk.call(credentials_fn: credentials_fn, auth: [host: "example.com", localtime_offset_msec: 1353788437000 - Now.msec()])
             |> Plug.Conn.send_resp()

      refute conn.halted
      assert conn.status == 200
      assert get_resp_header(conn, "server-authorization") == ["Hawk mac=\"k2ZrUnlfoyAwGyVVhcTDeNAFamE=\""]
    end

    test "parses a valid authentication header (host port override)", %{conn: conn, credentials_fn: credentials_fn} do
      conn = conn
             |> put_req_header("authorization", "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\"")
             |> Plug.Hawk.call(credentials_fn: credentials_fn, auth: [host: "example.com", port: 8080, localtime_offset_msec: 1353788437000 - Now.msec()])
             |> Plug.Conn.send_resp()

      refute conn.halted
      assert conn.status == 200
      assert get_resp_header(conn, "server-authorization") == ["Hawk mac=\"k2ZrUnlfoyAwGyVVhcTDeNAFamE=\""]
    end

    test "errors on an bad host header (missing host)", %{conn: conn, credentials_fn: credentials_fn} do
      conn = conn
             |> put_req_header("host", ":8080") |> put_req_header("authorization", "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"")
             |> Plug.Hawk.call(credentials_fn: credentials_fn, auth: [localtime_offset_msec: 1353788437000 - Now.msec()])
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {500, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid host header"} == sent_resp(conn)
    end

    test "errors on an bad host header (pad port)", %{conn: conn, credentials_fn: credentials_fn} do
      conn = conn
             |> put_req_header("host", "example.com:something")
             |> put_req_header("authorization", "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"")
             |> Plug.Hawk.call(credentials_fn: credentials_fn, auth: [localtime_offset_msec: 1353788437000 - Now.msec()])
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {500, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid host header"} == sent_resp(conn)
    end

    test "errors on a stale timestamp", %{conn: conn, credentials_fn: credentials_fn} do
      conn = %{conn | port: 8080, host: "example.com"}
             |> put_req_header("authorization", "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\"")
             |> Plug.Hawk.call(credentials_fn: credentials_fn)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      {status, headers, msg} = sent_resp(conn)
      header = for {"www-authenticate", value} <- headers, into: <<>>, do: value
      [ts, _tsm] = Regex.run(~r/^Hawk ts\=\"(\d+)\"\, tsm\=\"([^\"]+)\"\, error=\"Stale timestamp\"$/, header, capture: :all_but_first)
      now = Hawk.Now.sec()
      assert String.to_integer(ts, 10) in now-1000..now+1000
      assert status == 401
      assert msg == "Stale timestamp"
      assert {:ok, %{"www-authenticate" => %{error: "Stale timestamp", ts: _, tsm: _}}} = Hawk.Client.authenticate(headers, credentials_fn.("123456"), %{id: "123456", ts: "1362337299", nonce: "UzmxSs", ext: "some-app-data", mac: "wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=", port: 8080, host: "example.com"})
    end
  end
end
