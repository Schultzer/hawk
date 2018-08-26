defmodule HawkClientTest do
  use ExUnit.Case
  alias Hawk.{Client, Crypto, Now}

  describe "header/3" do
    test "returns a valid authorization header (sha1)" do
      credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :sha}
      %{header: header} = Client.header("http://example.net/somewhere/over/the/rainbow", :post, credentials, ext: "Bazinga!", ts: 1353809207, nonce: "Ygvqdz", payload: "something to write about")
      assert header == "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"bsvY3IfUllw6V5rvk4tStEvpBhE=\", ext=\"Bazinga!\", mac=\"qbf1ZPG/r/e06F4ht+T77LXi5vw=\""
    end

    test "returns a valid authorization header (sha256)" do
      credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :sha256}
      %{header: header} = Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ext: "Bazinga!", ts: 1353809207, nonce: "Ygvqdz", payload: "something to write about", content_type: "text/plain")
      assert header == "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", ext=\"Bazinga!\", mac=\"q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8=\""
    end

    test "returns a valid authorization header (no ext)" do
      credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :sha256}
      %{header: header} = Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ts: 1353809207, nonce: "Ygvqdz", payload: "something to write about", content_type: "text/plain")
      assert header == "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", mac=\"HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=\""
    end

    test "returns a valid authorization header (empty payload)" do
      credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :sha256}
      %{header: header} = Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ts: 1353809207, nonce: "Ygvqdz", payload: "", content_type: "text/plain")
      assert header == "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=\", mac=\"U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM=\""
    end

    test "returns a valid authorization header (pre hashed payload)" do
      credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :sha256}
      assert %{header: header} = Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ts: 1353809207, nonce: "Ygvqdz", payload: "something to write about", content_type: "text/plain", hash: Crypto.calculate_payload_hash(:sha256, "something to write about", "text/plain"))
      assert header == "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", mac=\"HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=\""
    end
  end

  def authenticate(_context) do
    [artifacts: %{
      method: "POST",
      host: "example.com",
      port: 8080,
      resource: "/resource/4?filter=a",
      ts: 1398546787,
      nonce: "xUwusx",
      hash: "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=",
      ext: "some-app-data",
      mac: "dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=",
      id: "123456"},
     credentials: %{id: "123456", key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, user: "steve"}
    ]
  end

  describe "authenticate/3" do
    setup :authenticate

    test "rejects on invalid header", result do
      assert {:error, {500, "Invalid Server-Authorization header"}} == Client.authenticate([{'server-authorization', 'Hawk mac="abc", bad="xyz"'}], result)
    end

    test "rejects on invalid mac", %{artifacts: artifacts} = result do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      result = Map.merge(result, %{artifacts: %{artifacts | ts: "1362336900", nonce: "eb5S_L", mac: "BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk="}})
      assert {:error, {500, "Bad response mac"}} == Client.authenticate(headers, result)
    end

    test "returns headers on ignoring hash", %{artifacts: artifacts} = result do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      result = Map.merge(result, %{artifacts: %{artifacts | ts: "1362336900", nonce: "eb5S_L", mac: "BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk="}})
      assert {:ok, %{"server-authorization" => %{mac: "XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash: "f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext: "response-specific"}}} == Client.authenticate(headers, result)
    end

    test "validates response payload", %{artifacts: artifacts} = result do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      result = Map.merge(result, %{artifacts: %{artifacts | ts: "1453070933", nonce: "3hOHpR", mac: "/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs="}})
      assert {:ok, %{"server-authorization" => %{mac: "odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash: "f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext: "response-specific"}}} == Client.authenticate(headers, result, payload: "some reply")
    end

    test "errors on invalid response payload", %{artifacts: artifacts} = result do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext=\"response-specific"'}]
      result = Map.merge(result, %{artifacts: %{artifacts | ts: "1453070933", nonce: "3hOHpR", mac: "/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs="}})
      assert {:error, {500, "Bad response payload mac"}} == Client.authenticate(headers, result, payload: "wrong reply")
    end

    test "fails on invalid WWW-Authenticate header format", result do
      assert {:error, {500, "Invalid WWW-Authenticate header"}} == Client.authenticate([{'www-authenticate', 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'}], result)
    end

    test "fails on invalid WWW-Authenticate header format (timestamp hash)", result do
      assert {:error, {500, "Invalid server timestamp hash"}} == Client.authenticate([{'www-authenticate', 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'}], result)
    end

    test "skips tsm validation when missing ts", result do
      assert {:ok, %{"www-authenticate" => %{error: "Stale timestamp"}}} == Client.authenticate([{'www-authenticate', 'Hawk error="Stale timestamp"'}], result)
    end
  end

  describe "message/6" do
    test "generates authorization" do
      credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :sha}
      auth = Client.message("example.com", 80, "I am the boodyman", credentials, timestamp: 1353809207, nonce: "abc123")
      assert auth.ts == 1353809207
      assert auth.nonce == "abc123"
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
      %{bewit: bewit} = Hawk.Client.get_bewit("https://example.com/somewhere/over/the/rainbow", credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec(), ext: "xandyandz")
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6"
    end

    test "returns a valid bewit value (explicit port)", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.Client.get_bewit("https://example.com:8080/somewhere/over/the/rainbow", credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec(), ext: "xandyandz")
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdcaFpiSjNQMmNLRW80a3kwQzhqa1pBa1J5Q1p1ZWc0V1NOYnhWN3ZxM3hIVT1ceGFuZHlhbmR6"
    end

    test "returns a valid bewit value (null ext), %{credentials: credentials}", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.Client.get_bewit("https://example.com/somewhere/over/the/rainbow", credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec())
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdcSUdZbUxnSXFMckNlOEN4dktQczRKbFdJQStValdKSm91d2dBUmlWaENBZz1c"
    end

    test "returns a valid bewit value (parsed uri)", %{credentials: credentials} do
      %{bewit: bewit} = Hawk.Client.get_bewit(URI.parse("https://example.com/somewhere/over/the/rainbow"), credentials, 300, localtime_offset_msec: 1356420407232 - Now.msec(), ext: "xandyandz")
      assert bewit == "MTIzNDU2XDEzNTY0MjA3MDdca3NjeHdOUjJ0SnBQMVQxekRMTlBiQjVVaUtJVTl0T1NKWFRVZEc3WDloOD1ceGFuZHlhbmR6"
    end
  end
end
