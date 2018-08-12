defmodule HawkClientTest do
  use ExUnit.Case
  alias Hawk.{Client, Crypto}

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
      %{header: header} = Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ts: 1353809207, nonce: "Ygvqdz", payload: "something to write about", content_type: "text/plain", hash: Crypto.calculate_payload_hash(:sha256, "something to write about", "text/plain"))
      assert header == "Hawk id=\"123456\", ts=\"1353809207\", nonce=\"Ygvqdz\", hash=\"2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=\", mac=\"HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs=\""
    end
  end

  def artifacts(_context) do
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
    setup :artifacts

    test "rejects on invalid header", %{artifacts: artifacts, credentials: credentials} do
      assert {:error, {500, "Invalid Server-Authorization header"}} == Client.authenticate([{'server-authorization', 'Hawk mac="abc", bad="xyz"'}], credentials, artifacts)
    end

    test "rejects on invalid mac", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      artifacts = %{artifacts | ts: "1362336900", nonce: "eb5S_L", mac: "BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk="}
      assert {:error, {500, "Bad response mac"}} == Client.authenticate(headers, credentials, artifacts)
    end

    test "returns headers on ignoring hash", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      artifacts = %{artifacts | ts: "1362336900", nonce: "eb5S_L", mac: "BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk="}
      assert {:ok, %{"server-authorization" => %{mac: "XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash: "f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext: "response-specific"}}} == Client.authenticate(headers, credentials, artifacts)
    end

    test "validates response payload", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      artifacts = %{artifacts | ts: "1453070933", nonce: "3hOHpR", mac: "/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs="}
      assert {:ok, %{"server-authorization" => %{mac: "odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash: "f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext: "response-specific"}}} == Client.authenticate(headers, credentials, artifacts, payload: "some reply")
    end

    test "errors on invalid response payload", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext=\"response-specific"'}]
      artifacts = %{artifacts | ts: "1453070933", nonce: "3hOHpR", mac: "/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs="}
      assert {:error, {500, "Bad response payload mac"}} == Client.authenticate(headers, credentials, artifacts, payload: "wrong reply")
    end

    test "fails on invalid WWW-Authenticate header format", %{artifacts: artifacts, credentials: credentials} do
      assert {:error, {500, "Invalid WWW-Authenticate header"}} == Client.authenticate([{'www-authenticate', 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'}], credentials, artifacts)
    end

    test "fails on invalid WWW-Authenticate header format (timestamp hash)", %{artifacts: artifacts, credentials: credentials}  do
      assert {:error, {500, "Invalid server timestamp hash"}} == Client.authenticate([{'www-authenticate', 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'}], credentials, artifacts)
    end

    test "skips tsm validation when missing ts", %{artifacts: artifacts, credentials: credentials} do
      assert {:ok, %{"www-authenticate" => %{error: "Stale timestamp"}}} == Client.authenticate([{'www-authenticate', 'Hawk error="Stale timestamp"'}], credentials, artifacts)
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
end
