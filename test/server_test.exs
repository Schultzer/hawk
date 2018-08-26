defmodule HawkServerTest do
  use ExUnit.Case
  alias Hawk.{Client, Crypto, Server, Now}

  defmodule Config do
    use Hawk.Config

    def get_credentials(id) do
      %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"}
    end
  end

  defmodule ConfigNonce do
    use Hawk.Config

    def get_credentials("123") do
      %{id: "123", key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"}
    end
    def get_credentials("456") do
      %{id: "456", key: "xrunpaw3489ruxnpa98w4rxnwerxhqb98rpaxn39848", algorithm: :sha256, user: "bob"}
    end
    def get_credentials(id) do
      %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"}
    end

    def nonce(key, nonce, _ts) do
      case :ets.lookup(:memory_cache, :c) do
        []                  ->
          :ets.insert(:memory_cache, c: {key, nonce})
          :ok

        [c: {^key, ^nonce}] -> :error # replay attack

        [c: {_key, ^nonce}]  -> :ok

        _                   -> :error
      end
    end
  end

  defmodule ConfigNonceFail do
    use Hawk.Config

    def get_credentials(id) do
      %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"}
    end

    def nonce(_key, _nonce, _ts), do: :error
  end

  defmodule ConfigFail do
    use Hawk.Config

    def get_credentials(_id), do: nil
  end

  defmodule ConfigId do
    use Hawk.Config

    def get_credentials(_id), do: %{key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", user: "steve"}
  end

  defmodule ConfigKey do
    use Hawk.Config

    def get_credentials(_id), do: %{id: "23434d3q4d5345d", user: "steve"}
  end

  defmodule ConfigAlgorithm do
    use Hawk.Config

    def get_credentials(id), do: %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: "hmac-sha-0", user: "steve"}
  end

  defmodule ConfigWrongKey do
    use Hawk.Config

    def get_credentials(id), do: %{id: id, key: "xxx", algorithm: :sha256, user: "steve"}
  end

  def authenticate(_context) do
    [
      credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"} end,
      request: %{method: "GET", url: "/resource/4?filter=a", host: "example.com", port: 8080, authorization: "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""}
    ]
  end

  describe "authenticate/3" do
    setup :authenticate

    test "parses a valid authentication header (sha1)", %{request: request} do
      assert {:ok, %{credentials: credentials}} = Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
      assert credentials.user == "steve"
    end

    test "parses a valid authentication header (sha256)", %{request: request} do
      request = %{request | url: "/resource/1?b=1&a=2", port: 8000, authorization: "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""}
      assert {:ok, %{credentials: credentials}} = Server.authenticate(request, Config, localtime_offset_msec: 1353832234000 - Now.msec())
      assert credentials.user == "steve"
    end

    test "parses a valid authentication header (POST with payload)", %{request: request} do
      request = %{request | method: "POST", authorization:  "Hawk id=\"123456\", ts=\"1357926341\", nonce=\"1AwuJD\", hash=\"qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=\", ext=\"some-app-data\", mac=\"UeYcj5UoTVaAWXNvJfLVia7kU3VabxCqrccXP8sUGC4=\""}
      assert {:ok, %{credentials: credentials}} = Server.authenticate(request, Config, localtime_offset_msec: 1357926341000 - Now.msec())
      assert credentials.user == "steve"
    end

    test "errors on missing hash", %{request: request} do
      request = %{request | url: "/resource/1?b=1&a=2", port: 8000, authorization: "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\""}
      assert {:error, {401, "Missing required payload hash", {"www-authenticate", "Hawk error=\"Missing required payload hash\""}}} == Server.authenticate(request, Config, payload: "body", localtime_offset_msec: 1353832234000 - Now.msec())
    end

    test "errors on a replay", %{request: request} do
      :ets.new(:memory_cache, [:named_table, :public, read_concurrency: true])
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""}
      options = [localtime_offset_msec: 1353788437000 - Now.msec()]
      assert {:ok, %{credentials: credentials}} = Server.authenticate(request, ConfigNonce, options)
      assert credentials.user == "steve"
      assert {:error, {401, "Invalid nonce", {"www-authenticate", "Hawk error=\"Invalid nonce\""}}} == Server.authenticate(request, ConfigNonce, options)
    end

    test "does not error on nonce collision if keys differ", %{request: request} do
      :ets.new(:memory_cache, [:named_table, :public, read_concurrency: true])
      steve = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"bXx7a7p1h9QYQNZ8x7QhvDQym8ACgab4m3lVSFn4DBw=\", ext=\"hello\""}
      bob = %{request | authorization: "Hawk id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"LXfmTnRzrLd9TD7yfH+4se46Bx6AHyhpM94hLCiNia4=\", ext=\"hello\""}
      options = [localtime_offset_msec: 1353788437000 - Now.msec()]

      assert {:ok, %{credentials: credentials1}} = Server.authenticate(steve, ConfigNonce, options)
      assert credentials1.user == "steve"
      assert {:ok, %{credentials: credentials2}} = Server.authenticate(bob, ConfigNonce, options)
      assert credentials2.user == "bob"
    end

    test "errors on an invalid authentication header: wrong scheme", %{request: request} do
      request = %{request | authorization: "Basic asdasdasdasd"}
      assert {:error, {401, "Unauthorized", {"www-authenticate", "Hawk"}}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an invalid authentication header: no scheme", %{request: request} do
      request = %{request | authorization: "!@#"}
      assert {:error, {400, "Invalid header syntax"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an missing authorization header", %{request: request} do
      assert {:error, {500, "Invalid host header"}} == Server.authenticate(Map.delete(request, :authorization), Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an missing authorization attribute (id)", %{request: request} do
      request = %{request | authorization: "Hawk ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Missing attributes"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an missing authorization attribute (ts)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Missing attributes"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an missing authorization attribute (nonce)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Missing attributes"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an missing authorization attribute (mac)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", ext=\"hello\""}
      assert {:error, {400, "Missing attributes"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an unknown authorization attribute", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", x=\"3\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Unknown attribute: x"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an bad authorization header format", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\\\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Bad attribute value: \\"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
      # :bad_header_format
    end

    test "errors on an bad authorization attribute value", %{request: request} do
      request = %{request | authorization: "Hawk id=\"\t\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Bad attribute value: \t"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an empty authorization attribute value", %{request: request} do
      request = %{request | authorization: "Hawk id=\"\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Bad attribute value: \""}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on duplicated authorization attribute key", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", id=\"456\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {400, "Duplicate attribute: id"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on an invalid authorization header format", %{request: request} do
      request = %{request | authorization: "Hawk"}
      assert {:error, {400, "Invalid header syntax"}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on credentials_fn error", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate(request, ConfigFail, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on credentials_fn error (with credentials)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate(request, ConfigFail, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on missing credentials", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate(request, ConfigFail, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on invalid credentials (id)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {500, "Invalid credentials"}} == Server.authenticate(request, ConfigId, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on invalid credentials (key)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {500, "Invalid credentials"}} == Server.authenticate(request, ConfigKey, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on unknown credentials algorithm", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {500, "Unknown algorithm"}} == Server.authenticate(request, ConfigAlgorithm, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on unknown bad mac", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcU4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""}
      assert {:error, {401, "Bad mac", {"www-authenticate", "Hawk error=\"Bad mac\""}}} == Server.authenticate(request, Config, localtime_offset_msec: 1353788437000 - Now.msec())
    end

    test "errors on a stale timestamp", %{request: request} do
      request = %{request | authorization: "Hawk id=\"123456\", ts=\"1362337299\", nonce=\"UzmxSs\", ext=\"some-app-data\", mac=\"wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=\""}
      {:error, {401, "Stale timestamp", {"www-authenticate", value} = header}} = Hawk.Server.authenticate(request, Config)
      [ts, _tsm] = Regex.run(~r/^Hawk ts\=\"(\d+)\"\, tsm\=\"([^\"]+)\"\, error=\"Stale timestamp\"$/, value, capture: :all_but_first)
      now = Hawk.Now.sec()
      assert String.to_integer(ts, 10) in now-1000..now+1000
      assert {:ok, %{"www-authenticate" => %{error: "Stale timestamp", ts: _, tsm: _}}} = Hawk.Client.authenticate([header], %{credentials: Config.get_credentials("123456"), artifacts: %{id: "123456", ts: "1362337299", nonce: "UzmxSs", ext: "some-app-data", mac: "wnNUxchvvryMH2RxckTdZ/gY3ijzvccx4keVvELC61w=", port: 8080, host: "example.com"}})
    end

    test "parses a valid authentication header (host port override)", %{request: request} do
      request = %{request | authorization: "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""}
      assert {:ok, %{artifacts: %{port: 8080}}} = Server.authenticate(request, Config, host: "example.com", port: 8080, localtime_offset_msec: 1353788437000 - Now.msec())
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

    test "generates header", result do
      header = Server.header(result, payload: "some reply", content_type: "text/plain", ext: "response-specific")
      assert header == "Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\""
    end

    test "generates header (empty payload)", result do
      header = Server.header(result, payload: "", content_type: "text/plain", ext: "response-specific")
      assert header == "Hawk mac=\"i8/kUBDx0QF+PpCtW860kkV/fa9dbwEoe/FpGUXowf0=\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", ext=\"response-specific\""
    end

    test "generates header (pre calculated hash)", result do
      payload = "some reply"
      content_type = "text/plain"
      header = Server.header(result, payload: payload, content_type: content_type, ext: "response-specific", hash: Crypto.calculate_payload_hash(:sha256, payload, content_type))
      assert header == "Hawk mac=\"n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\", ext=\"response-specific\""
    end

    test "generates header (no ext)", %{artifacts: artifacts, credentials: credentials} do
      header = Server.header(%{credentials: credentials, artifacts: Map.delete(artifacts, :ext)}, payload: "some reply", content_type: "text/plain")
      assert header == "Hawk mac=\"6PrybJTJs20jsgBw5eilXpcytD8kUbaIKNYXL+6g0ns=\", hash=\"f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=\""
    end
  end

  def authenticate_bewit(_context) do
    [
      request: %{method: "GET", url: "/resource/4?a=1&b=2", host: "example.com", port: 80}
    ]
  end

  describe "authenticate_bewit/3" do
    setup :authenticate_bewit
    test "errors on uri too long" do
      assert {:error, {400, "Resource path exceeds max length"}} == Server.authenticate_bewit(%{method: "GET", url: (for _ <- 1..5000, into: <<>>, do: <<?x>>), host: "example.com", port: 8080, authorization: "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""}, Config)
    end

    test "should generate a bewit then successfully authenticate it", %{request: request} do
      %{bewit: bewit} = Client.get_bewit("http://example.com/resource/4?a=1&b=2", Config.get_credentials("123456"), 60 * 60 * 24 * 365 * 100, ext: "some-app-data")
      request = Map.update!(request, :url,  &(&1 <> "&bewit=#{bewit}"))
      {:ok, %{attributes: attributes, credentials: credentials}} = Server.authenticate_bewit(request, Config)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should generate a bewit then successfully authenticate it (no ext)", %{request: request}  do
      %{bewit: bewit} = Client.get_bewit("http://example.com/resource/4?a=1&b=2", Config.get_credentials("123456"), 60 * 60 * 24 * 365 * 100)
      request = Map.update!(request, :url, &(&1 <> "&bewit=#{bewit}"))
      {:ok, %{credentials: credentials}} = Server.authenticate_bewit(request, Config)
      assert credentials.user == "steve"
    end

    test "should successfully authenticate a request (last param)", %{request: request}  do
      request = %{request | port: 8080, url: "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"}
      {:ok, %{credentials: credentials, attributes: attributes}} = Server.authenticate_bewit(request, Config)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should successfully authenticate a request (first param)", %{request: request}  do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ&a=1&b=2"}
      {:ok, %{credentials: credentials, attributes: attributes}} = Server.authenticate_bewit(request, Config)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should successfully authenticate a request (only param)", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ"}
      {:ok, %{credentials: credentials, attributes: attributes}} = Server.authenticate_bewit(request, Config)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should fail on multiple authentication", %{request: request} do
      request = Map.merge(request, %{authorization: "Basic asdasdasdasd", port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ"})
      assert {:error, {400, "Multiple authentications"}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on method other than GET", %{request: request} do
      request = %{request | method: "POST", port: 8080, url: "/resource/4?filter=a"}
      credentials = Config.get_credentials("123456")
      exp = :math.floor(Now.msec() / 1000) + 60;
      ext = "some-app-data"
      mac = Crypto.calculate_mac("bewit", credentials, ts: exp, nonce: '', method: request.method, resource: request.url, host: request.host, port: request.port, ext: ext)
      bewit = "#{credentials.id}\\#{exp}\\#{mac}\\#{ext}"
      request = Map.update!(request, :url, &(&1 <> "&bewit=#{Base.url_encode64(bewit)}"))
      assert {:error, {401, "Invalid method", {"www-authenticate", "Hawk error=\"Invalid method\""}}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on empty bewit", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit="}
      assert {:error, {401, "Empty bewit", {"www-authenticate", "Hawk error=\"Empty bewit\""}}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on invalid bewit", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=*"}
      assert {:error, {400, "Invalid bewit encoding"}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on missing bewit", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4"}
      assert {:error, {400, "Invalid bewit encoding"}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on invalid bewit structure", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=abc"}
      assert {:error, {400, "Invalid bewit structure"}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on empty bewit attribute", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=YVxcY1xk"}
      assert {:error, {400, "Missing bewit attributes"}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on missing bewit id attribute", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=XDQ1NTIxNDc2MjJcK0JFbFhQMXhuWjcvd1Nrbm1ldGhlZm5vUTNHVjZNSlFVRHk4NWpTZVJ4VT1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {400, "Missing bewit attributes"}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on expired access", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?a=1&b=2&bewit=MTIzNDU2XDEzNTY0MTg1ODNcWk1wZlMwWU5KNHV0WHpOMmRucTRydEk3NXNXTjFjeWVITTcrL0tNZFdVQT1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Access expired", {"www-authenticate", "Hawk error=\"Access expired\""}}} == Server.authenticate_bewit(request, Config)
    end

    test "should fail on credentials function error,", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate_bewit(request, ConfigFail)
    end

    test "should fail on credentials function error with credentials", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate_bewit(request, ConfigFail)
    end

    test "should fail on null credentials function response", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate_bewit(request, ConfigFail)
    end

    test "should fail on invalid credentials function response", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {500, "Invalid credentials"}} == Server.authenticate_bewit(request, ConfigId)
    end

    test "should fail on invalid credentials function response (unknown algorithm)", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {500, "Unknown algorithm"}} == Server.authenticate_bewit(request, ConfigAlgorithm)
    end

    test "should fail on invalid credentials function response (bad mac)", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Bad mac", {"www-authenticate", "Hawk error=\"Bad mac\""}}} == Server.authenticate_bewit(request, ConfigWrongKey)
    end
  end
  def authenticate_message(_context) do
    [
      authorization: Client.message("example.com" , 8080, "some message", %{id: "123456", key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"}),
    ]
  end

  describe "authenticate_message/6" do
    setup :authenticate_message

    test "errors on invalid authorization (ts)", %{authorization: authorization} do
      assert {:error, {400, "Invalid authorization"}} == Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :ts), Config)
    end

    test "errors on invalid authorization (nonce)", %{authorization: authorization} do
      assert {:error, {400, "Invalid authorization"}} == Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :nonce), Config)
    end

    test "errors on invalid authorization (hash)", %{authorization: authorization} do
      assert {:error, {400, "Invalid authorization"}} == Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :hash), Config)
    end

    test "errors with credentials", %{authorization: authorization} do
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigFail)
    end

    test "errors on nonce collision", %{authorization: authorization} do
      assert {:error, {401, "Invalid nonce", {"www-authenticate", "Hawk error=\"Invalid nonce\""}}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigNonceFail)
    end

    test "should generate an authorization then successfully parse it", %{authorization: authorization} do
      {:ok, %{credentials: credentials}} = Server.authenticate_message("example.com", 8080, "some message", authorization, Config)
      assert credentials.user == "steve"
    end

    test "should fail authorization on mismatching host", %{authorization: authorization} do
      assert {:error, {401, "Bad mac", {"www-authenticate", "Hawk error=\"Bad mac\""}}} == Server.authenticate_message("example1.com", 8080, "some message", authorization, Config)
    end

    test "should fail authorization on stale timestamp", %{authorization: authorization} do
      assert {:error, {401, "Stale timestamp", {"www-authenticate", "Hawk error=\"Stale timestamp\""}}} == Server.authenticate_message("example.com", 8080, "some message", authorization, Config, localtime_offset_msec: 100000)
    end

    test "overrides timestamp_skew_sec" do
      authorization = Client.message("example.com", 8080, "some message", Config.get_credentials("123456"), localtime_offset_msec: 100000)
      assert {:ok, _} = Server.authenticate_message("example.com", 8080, "some message", authorization, Config, timestamp_skew_sec: 500)
    end

    test "should fail authorization on invalid authorization", %{authorization: authorization} do
      assert {:error, {400, "Invalid authorization"}} == Server.authenticate_message("example.com", 8080, "some message", Map.delete(authorization, :id), Config)
    end

    test "should fail authorization on bad hash", %{authorization: authorization} do
      assert {:error, {401, "Bad message hash", {"www-authenticate", "Hawk error=\"Bad message hash\""}}} == Server.authenticate_message("example.com", 8080, "some message1", authorization, Config)
    end

    test "should fail authorization on nonce error", %{authorization: authorization} do
      assert {:error, {401, "Invalid nonce", {"www-authenticate", "Hawk error=\"Invalid nonce\""}}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigNonceFail)
    end

    test "should fail authorization on credentials error", %{authorization: authorization} do
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigFail)
    end

    test "should fail authorization on missing credentials", %{authorization: authorization} do
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigFail)
    end

    test "should fail authorization on invalid credentials", %{authorization: authorization} do
      assert {:error, {500, "Invalid credentials"}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigId)
    end

    test "should fail authorization on invalid credentials algorithm", %{authorization: authorization} do
      assert {:error, {500, "Unknown algorithm"}} == Server.authenticate_message("example.com", 8080, "some message", authorization, ConfigAlgorithm)
    end
  end

  describe "authenticate_payload_hash/2" do
    test "checks payload hash" do
      assert {:ok, %{artifacts: %{hash: "abcdefg"}}} == Server.authenticate_payload_hash("abcdefg", %{hash: "abcdefg"})
      assert {:error, {401, "Bad payload hash", {"www-authenticate", "Hawk error=\"Bad payload hash\""}}} == Server.authenticate_payload_hash("1234567", %{hash: "abcdefg"})
    end
  end
end
