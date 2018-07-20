defmodule HawkServerTest do
  use ExUnit.Case
  alias Hawk.{Client, Crypto, Server, Now}

  def authenticate(_context) do
    [
      credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"} end,
      request: %{method: "GET", url: "/resource/4?filter=a", host: "example.com", port: 8080, authorization: "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""}
    ]
  end

  describe "authenticate/3" do
    setup :authenticate

    test "parses a valid authentication header (sha1)", %{credentials_fn: credentials_fn, request: request} do
      assert %{credentials: credentials} = Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      assert credentials.user == "steve"
    end

    test "parses a valid authentication header (sha256)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | url: "/resource/1?b=1&a=2", port: 8000, authorization: "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""}
      assert %{credentials: credentials} = Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353832234000 - Now.msec())
      assert credentials.user == "steve"
    end

    test "parses a valid authentication header (POST with payload)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | method: "POST", authorization:  "Hawk id=\"123456\", ts=\"1357926341\", nonce=\"1AwuJD\", hash=\"qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=\", ext=\"some-app-data\", mac=\"UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4=\""}
      assert %{credentials: credentials} = Server.authenticate(request, credentials_fn, localtime_offset_msec: 1357926341000 - Now.msec())
      assert credentials.user == "steve"
    end

    test "errors on missing hash", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | url: "/resource/1?b=1&a=2", port: 8000, authorization: "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""}
      assert_raise Hawk.Unauthorized, "Missing required payload hash", fn ->
        Server.authenticate(request, credentials_fn, payload: "body", localtime_offset_msec: 1353832234000 - Now.msec())
      end
    end

    test "errors on a replay", %{credentials_fn: credentials_fn, request: request} do
      :ets.new(:memory_cache, [:named_table, :public, read_concurrency: true])
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""}
      nonce_fn = fn(key, nonce, _ts) ->
        case :ets.lookup(:memory_cache, :c) do
          []                  ->
            :ets.insert(:memory_cache, c: {key, nonce})
            :ok

          [c: {^key, ^nonce}] -> :error # replay attack

          _                   -> :error
        end
      end
      options = [localtime_offset_msec: 1353788437000 - Now.msec(), nonce_fn: nonce_fn]
      assert %{credentials: credentials} = Server.authenticate(request, credentials_fn, options)
      assert credentials.user == "steve"
      assert_raise Hawk.Unauthorized, "Invalid nonce", fn ->
        Server.authenticate(request, credentials_fn, options)
      end
    end

    test "does not error on nonce collision if keys differ", %{request: request} do
      :ets.new(:memory_cache, [:named_table, :public, read_concurrency: true])
      steve = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""}
      bob = %{request | authorization: "Hawk id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"LXfmTnRzrLd9TD7yfH+4se46Bx6AHyhpM94hLCiNia4=\", ext=\"hello\""}
      credentials_function = fn id ->
        credentials = %{"123" => %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"},
                        "456" => %{id: id, key: "xrunpaw3489ruxnpa98w4rxnwerxhqb98rpaxn39848", algorithm: :sha256, user: "bob"}}
        credentials[id]
      end
      nonce_fn = fn(key, nonce, _ts) ->
        case :ets.lookup(:memory_cache, :c) do
          []                   ->
            :ets.insert(:memory_cache, c: {key, nonce})
            :ok

          [c: {^key, ^nonce}]  -> :error # replay attack

          [c: {_key, ^nonce}]  -> :ok
        end
      end
      options = [localtime_offset_msec: 1353788437000 - Now.msec(), nonce_fn: nonce_fn]

      assert %{credentials: credentials1} = Server.authenticate(steve, credentials_function, options)
      assert credentials1.user == "steve"
      assert %{credentials: credentials2}  = Server.authenticate(bob, credentials_function, options)
      assert credentials2.user == "bob"
    end

    test "errors on an invalid authentication header: wrong scheme", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Basic asdasdasdasd"}
      assert_raise Hawk.Unauthorized, "Hawk", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an invalid authentication header: no scheme", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "!@#"}
      assert_raise Hawk.BadRequest, "Invalid header syntax", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an missing authorization header", %{credentials_fn: credentials_fn, request: request} do
      assert_raise Hawk.InternalServerError, "Invalid host header", fn ->
        Server.authenticate(Map.delete(request, :authorization), credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an missing authorization attribute (id)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Missing attributes", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an missing authorization attribute (ts)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"123\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Missing attributes", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an missing authorization attribute (nonce)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Missing attributes", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an missing authorization attribute (mac)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Missing attributes", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an unknown authorization attribute", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", x=\"3\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Unknown attribute", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an bad authorization header format", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"123\\\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Bad attribute value", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
      # :bad_header_format
    end

    test "errors on an bad authorization attribute value", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"\t\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Bad attribute value", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an empty authorization attribute value", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Bad attribute value", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on duplicated authorization attribute key", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk id=\"123\", id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.BadRequest, "Duplicate attribute", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on an invalid authorization header format", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | authorization: "Hawk"}
      assert_raise Hawk.BadRequest, "Invalid header syntax", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on credentials_fn error", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.Unauthorized, "Unknown credentials", fn ->
        Server.authenticate(request, fn (_id) -> {:error, "unknown user"} end, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on credentials_fn error (with credentials)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.Unauthorized, "Unknown credentials", fn ->
        Server.authenticate(request, fn (_id) -> {:error, "unknown user"} end, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on missing credentials", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.Unauthorized, "Unknown credentials", fn ->
        Server.authenticate(request, fn (_id) -> nil end, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on invalid credentials (id)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise  Hawk.InternalServerError, "Invalid credentials", fn ->
        Server.authenticate(request, fn (_id) -> %{key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", user: "steve"} end, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on invalid credentials (key)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.InternalServerError, "Invalid credentials", fn ->
        Server.authenticate(request, fn (_id) -> %{id: "23434d3q4d5345d", user: "steve"} end, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on unknown credentials algorithm", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.Unauthorized, "Unknown algorithm", fn ->
        Server.authenticate(request, fn (id) -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: "hmac-sha-0", user: "steve"} end, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end

    test "errors on unknown bad mac", %{request: request, credentials_fn: credentials_fn} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert_raise Hawk.Unauthorized, "Bad mac", fn ->
        Server.authenticate(request, credentials_fn, localtime_offset_msec: 1353788437000 - Now.msec())
      end
    end
  end

  def header(_context) do
    [
      artifacts: %{ext: "some-app-data", hash: "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=", host: "example.com", id: "123456", mac: "dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=", method: "POST", nonce: "xUwusx", port: 8080, resource: "/resource/4?filter=a", ts: 1398546787},
      credentials: %{algorithm: :sha256, id: "123456", key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", user: "steve"
      }
    ]
  end

  describe "header/3" do
    setup :header

    test "generates header", %{artifacts: artifacts, credentials: credentials} do
      header = Server.header(credentials, artifacts, payload: "some reply", content_type: "text/plain", ext: "response-specific")
      assert header == "Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\""
    end

    test "generates header (empty payload)", %{artifacts: artifacts, credentials: credentials} do
      header = Server.header(credentials, artifacts, payload: "", content_type: "text/plain", ext: "response-specific")
      assert header == "Hawk mac=\"i8/kUBDx0QF+PpCtW860kkV/fa9dbwEoe/FpGUXowf0=\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", ext=\"response-specific\""
    end

    test "generates header (pre calculated hash)", %{artifacts: artifacts, credentials: credentials} do
      payload = "some reply"
      content_type = "text/plain"
      header = Server.header(credentials, artifacts, payload: payload, content_type: content_type, ext: "response-specific", hash: Crypto.calculate_payload_hash(:sha256, payload, content_type))
      assert header == "Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\""
    end

    test "generates header (no ext)", %{artifacts: artifacts, credentials: credentials} do
      header = Server.header(credentials, Map.delete(artifacts, :ext), payload: "some reply", content_type: "text/plain")
      assert header == "Hawk mac=\"6PrybJTJs20jsgBw5eilXpcytD8kUbaIKNYXL+6g0ns=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\""
    end
  end

  def authenticate_bewit(_context) do
    [
      credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"} end
    ]
  end

  describe "authenticate_bewit/3" do
    setup :authenticate_bewit
    test "errors on uri too long", %{credentials_fn: credentials_fn} do
      assert_raise Hawk.BadRequest, "Resource path exceeds max length", fn ->
        Server.authenticate_bewit(%{method: "GET", url: (for _ <- 1..5000, into: <<>>, do: <<?x>>), host: "example.com", port: 8080, authorization: "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""}, credentials_fn)
      end
    end
  end

  def authenticate_message(_context) do
    [
      authorization: Client.message("example.com" , 8080, "some message", %{id: "123456", key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"}),
      credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"} end
    ]
  end

  describe "authenticate_message/6" do
    setup :authenticate_message

    test "errors on invalid authorization (ts)", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.BadRequest, "Invalid authorization", fn ->
        Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :ts), credentials_fn)
      end
    end

    test "errors on invalid authorization (nonce)", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.BadRequest, "Invalid authorization", fn ->
        Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :nonce), credentials_fn)
      end
    end

    test "errors on invalid authorization (hash)", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.BadRequest, "Invalid authorization", fn ->
        Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :hash), credentials_fn)
      end
    end

    test "errors with credentials", %{authorization: authorization} do
      assert_raise Hawk.Unauthorized, "Unknown credentials", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, fn(_) -> :error end)
      end
    end

    test "errors on nonce collision", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.Unauthorized, "Invalid nonce", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, credentials_fn, nonce_fn: fn(_key, _nonce, _ts) -> {:error, "nonce collision"} end)
      end
    end

    test "should generate an authorization then successfully parse it", %{authorization: authorization, credentials_fn: credentials_fn} do
      result = Server.authenticate_message("example.com", 8080, "some message", authorization, credentials_fn)
      assert result.credentials.user == "steve"
    end

    test "should fail authorization on mismatching host", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.Unauthorized, "Bad mac", fn ->
        Server.authenticate_message("example1.com", 8080, "some message", authorization, credentials_fn)
      end
    end

    test "should fail authorization on stale timestamp", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.Unauthorized, "Stale timestamp", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, credentials_fn, localtime_offset_msec: 100000)
      end
    end

    test "overrides timestamp_skew_sec", %{credentials_fn: credentials_fn} do
      authorization = Client.message("example.com", 8080, "some message", credentials_fn.("123456"), localtime_offset_msec: 100000)
      assert is_map Server.authenticate_message("example.com", 8080, "some message", authorization, credentials_fn, timestamp_skew_sec: 500)
    end

    test "should fail authorization on invalid authorization", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.BadRequest, "Invalid authorization", fn ->
        Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :id), credentials_fn)
      end
    end

    test "should fail authorization on bad hash", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.Unauthorized, "Bad payload hash", fn ->
        Server.authenticate_message("example.com", 8080, "some message1", authorization, credentials_fn)
      end
      #{:error, "Bad message hash"}
    end

    test "should fail authorization on nonce error", %{authorization: authorization, credentials_fn: credentials_fn} do
      assert_raise Hawk.Unauthorized, "Invalid nonce", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, credentials_fn, nonce_fn: fn (_key, _nonce, _ts) -> {:error, "kaboom"} end)
      end
    end

    test "should fail authorization on credentials error", %{authorization: authorization} do
      assert_raise Hawk.Unauthorized, "Unknown credentials", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, fn (_id) -> {:error, "kablooey"} end)
      end
    end

    test "should fail authorization on missing credentials", %{authorization: authorization} do
      assert_raise Hawk.Unauthorized, "Unknown credentials", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, fn (_id) -> :error end)
      end
    end

    test "should fail authorization on invalid credentials", %{authorization: authorization} do
      assert_raise Hawk.InternalServerError, "Invalid credentials", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, fn (_id) -> %{} end)
      end
    end

    test "should fail authorization on invalid credentials algorithm", %{authorization: authorization} do
      assert_raise Hawk.Unauthorized, "Unknown algorithm", fn ->
        Server.authenticate_message("example.com", 8080, "some message", authorization, fn (_id) -> %{key: "123", algorithm: "456"} end)
      end
    end
  end

  describe "authenticate_payload_hash/2" do
    test "checks payload hash" do
      assert Server.authenticate_payload_hash("abcdefg", %{hash: "abcdefg"}) == %{artifacts: %{hash: "abcdefg"}}
      assert_raise Hawk.Unauthorized, "Bad payload hash", fn ->
        Server.authenticate_payload_hash("1234567", %{hash: "abcdefg"})
      end
    end
  end
end
