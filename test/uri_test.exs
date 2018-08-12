defmodule HawkUriTest do
  use ExUnit.Case
  alias Hawk.{Crypto, Now}

  def authenticate(_context) do
    [
      credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"} end,
      request: %{method: "GET", url: "/resource/4?a=1&b=2", host: "example.com", port: 80}
    ]
  end

  describe "authenticate/3" do
    setup :authenticate
    test "should generate a bewit then successfully authenticate it", %{credentials_fn: credentials_fn, request: request} do
      %{bewit: bewit} = Hawk.URI.get_bewit("http://example.com/resource/4?a=1&b=2", credentials_fn.("123456"), 60 * 60 * 24 * 365 * 100, ext: "some-app-data")
      request = Map.update!(request, :url,  &(&1 <> "&bewit=#{bewit}"))
      {:ok, %{attributes: attributes, credentials: credentials}} = Hawk.URI.authenticate(request, credentials_fn)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should generate a bewit then successfully authenticate it (no ext)", %{credentials_fn: credentials_fn, request: request}  do
      %{bewit: bewit} = Hawk.URI.get_bewit("http://example.com/resource/4?a=1&b=2", credentials_fn.("123456"), 60 * 60 * 24 * 365 * 100)
      request = Map.update!(request, :url, &(&1 <> "&bewit=#{bewit}"))
      {:ok, %{credentials: credentials}} = Hawk.URI.authenticate(request, credentials_fn)
      assert credentials.user == "steve"
    end

    test "should successfully authenticate a request (last param)", %{credentials_fn: credentials_fn, request: request}  do
      request = %{request | port: 8080, url: "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"}
      {:ok, %{credentials: credentials, attributes: attributes}} = Hawk.URI.authenticate(request, credentials_fn)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should successfully authenticate a request (first param)", %{credentials_fn: credentials_fn, request: request}  do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ&a=1&b=2"}
      {:ok, %{credentials: credentials, attributes: attributes}} = Hawk.URI.authenticate(request, credentials_fn)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should successfully authenticate a request (only param)", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ"}
      {:ok, %{credentials: credentials, attributes: attributes}} = Hawk.URI.authenticate(request, credentials_fn)
      assert credentials.user == "steve"
      assert attributes.ext == "some-app-data"
    end

    test "should fail on multiple authentication", %{credentials_fn: credentials_fn, request: request} do
      request = Map.merge(request, %{authorization: "Basic asdasdasdasd", port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ"})
      assert {:error, {400, "Multiple authentications"}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on method other than GET", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | method: "POST", port: 8080, url: "/resource/4?filter=a"}
      credentials = credentials_fn.("123456")
      exp = :math.floor(Now.msec() / 1000) + 60;
      ext = "some-app-data"
      mac = Crypto.calculate_mac("bewit", credentials, ts: exp, nonce: '', method: request.method, resource: request.url, host: request.host, port: request.port, ext: ext)
      bewit = "#{credentials.id}\\#{exp}\\#{mac}\\#{ext}"
      request = Map.update!(request, :url, &(&1 <> "&bewit=#{Base.url_encode64(bewit)}"))
      assert {:error, {401, "Invalid method", {"www-authenticate", "Hawk error=\"Invalid method\""}}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on empty bewit", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit="}
      assert {:error, {401, "Empty bewit", {"www-authenticate", "Hawk error=\"Empty bewit\""}}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on invalid bewit", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=*"}
      assert {:error, {400, "Invalid bewit encoding"}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on missing bewit", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4"}
      assert {:error, {400, "Invalid bewit encoding"}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on invalid bewit structure", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=abc"}
      assert {:error, {400, "Invalid bewit structure"}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on empty bewit attribute", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=YVxcY1xk"}
      assert {:error, {400, "Missing bewit attributes"}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on missing bewit id attribute", %{credentials_fn: credentials_fn, request: request} do
     request = %{request | port: 8080, url: "/resource/4?bewit=XDQ1NTIxNDc2MjJcK0JFbFhQMXhuWjcvd1Nrbm1ldGhlZm5vUTNHVjZNSlFVRHk4NWpTZVJ4VT1cc29tZS1hcHAtZGF0YQ"}
     assert {:error, {400, "Missing bewit attributes"}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on expired access", %{credentials_fn: credentials_fn, request: request} do
      request = %{request | port: 8080, url: "/resource/4?a=1&b=2&bewit=MTIzNDU2XDEzNTY0MTg1ODNcWk1wZlMwWU5KNHV0WHpOMmRucTRydEk3NXNXTjFjeWVITTcrL0tNZFdVQT1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Access expired", {"www-authenticate", "Hawk error=\"Access expired\""}}} == Hawk.URI.authenticate(request, credentials_fn)
    end

    test "should fail on credentials function error,", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Hawk.URI.authenticate(request, fn(_) -> :error end)
    end

    test "should fail on credentials function error with credentials", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Hawk.URI.authenticate(request, fn(_) -> :error end)
    end

    test "should fail on null credentials function response", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Unknown credentials", {"www-authenticate", "Hawk error=\"Unknown credentials\""}}} == Hawk.URI.authenticate(request, fn(_) -> nil end)
    end

    test "should fail on invalid credentials function response", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {500, "Invalid credentials"}} == Hawk.URI.authenticate(request, fn(_) -> %{} end)
    end

    test "should fail on invalid credentials function response (unknown algorithm)", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {500, "Unknown algorithm"}} == Hawk.URI.authenticate(request,  fn(_) -> %{key: "xxx", algorithm: "xxx"} end)
    end

    test "should fail on invalid credentials function response (bad mac)", %{request: request} do
      request = %{request | port: 8080, url: "/resource/4?bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQ"}
      assert {:error, {401, "Bad mac", {"www-authenticate", "Hawk error=\"Bad mac\""}}} == Hawk.URI.authenticate(request, fn(_) -> %{key: "xxx", algorithm: :sha256} end)
    end
  end

  def get_bewit(_context) do
    [
      credentials: %{id: "123456", key: "2983d45yun89q", algorithm: :sha256}
    ]
  end

  describe "get_bewit/2" do
    setup :get_bewit
    test "returns a valid bewit value", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.URI.get_bewit("https://example.com/somewhere/over/the/rainbow", credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec(), ext: "xandyandz")
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6"
    end

    test "returns a valid bewit value (explicit port)", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.URI.get_bewit("https://example.com:8080/somewhere/over/the/rainbow", credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec(), ext: "xandyandz")
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6"
    end

    test "returns a valid bewit value (null ext), %{credentials: credentials}", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.URI.get_bewit("https://example.com/somewhere/over/the/rainbow", credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec())
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c"
    end

    test "returns a valid bewit value (parsed uri)", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.URI.get_bewit(URI.parse("https://example.com/somewhere/over/the/rainbow"), credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec(), ext: "xandyandz")
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6"
    end
  end
end
