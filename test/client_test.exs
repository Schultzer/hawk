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

    # test "errors on missing uri" do
    #   assert Client.header("", :post, %{}) == :invalid_uri
    # end

    # test "errors on invalid uri" do
    #   assert Client.header(4, :post, %{}) == :invalid_uri
    # end

    # test "errors on missing method" do
    #   assert Client.header("https://example.net/somewhere/over/the/rainbow", "", %{}) == :unknown_method
    # end

    # test "errors on invalid method" do
    #   assert Client.header("https://example.net/somewhere/over/the/rainbow", 4, %{}) == :unknown_method
    # end

    # test "errors on invalid credentials (id)" do
    #   credentials = %{key: "2983d45yun89q", algorithm: :sha256}
    #   assert Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ext: 'Bazinga!', timestamp: 1353809207) == :invalid_credentials
    # end

    # test "errors on missing credentials" do
    #   assert Client.header("https://example.net/somewhere/over/the/rainbow", :post, %{}, ext: "Bazinga!", timestamp: 1353809207) == :invalid_credentials
    # end

    # test "errors on invalid credentials" do
    #   credentials = %{id: "123456", algorithm: :sha256}
    #   assert Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, ext: "Bazinga!", timestamp: 1353809207) == :invalid_credentials
    # end

    # test "errors on invalid algorithm" do
    #   credentials = %{id: "123456", key: "2983d45yun89q", algorithm: :hmac_sha_0}
    #   assert Client.header("https://example.net/somewhere/over/the/rainbow", :post, credentials, payload: "something, anything!", ext: "Bazinga!", timestamp: 1353809207) == :unknown_algorithm
    # end
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
      assert_raise Hawk.InternalServerError, "Invalid Server-Authorization header", fn ->
        Client.authenticate([{'server-authorization', 'Hawk mac="abc", bad="xyz"'}], credentials, artifacts)
      end
    end

    test "rejects on invalid mac", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      artifacts = %{artifacts | ts: "1362336900", nonce: "eb5S_L", mac: "BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk="}
      assert_raise Hawk.InternalServerError, "Bad response mac", fn ->
        Client.authenticate(headers, credentials, artifacts)
      end
    end

    test "returns headers on ignoring hash", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      artifacts = %{artifacts | ts: "1362336900", nonce: "eb5S_L", mac: "BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk="}
      assert Client.authenticate(headers, credentials, artifacts) == %{"server-authorization" => %{mac: "XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash: "f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext: "response-specific"}}
    end

    test "validates response payload", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"'}]
      artifacts = %{artifacts | ts: "1453070933", nonce: "3hOHpR", mac: "/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs="}
      assert Client.authenticate(headers, credentials, artifacts, payload: "some reply") == %{"server-authorization" => %{mac: "odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash: "f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext: "response-specific"}}
    end

    test "errors on invalid response payload", %{artifacts: artifacts, credentials: credentials} do
      headers = [{'content-type', 'text/plain'}, {'server-authorization', 'Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext=\"response-specific"'}]
      artifacts = %{artifacts | ts: "1453070933", nonce: "3hOHpR", mac: "/DitzeD66F2f7O535SERbX9p+oh9ZnNLqSNHG+c7/vs="}
      assert_raise Hawk.InternalServerError, "Bad response payload mac", fn ->
        Client.authenticate(headers, credentials, artifacts, payload: "wrong reply")
      end
    end

    test "fails on invalid WWW-Authenticate header format", %{artifacts: artifacts, credentials: credentials} do
      assert_raise Hawk.InternalServerError, "Invalid WWW-Authenticate header", fn ->
        Client.authenticate([{'www-authenticate', 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"'}], credentials, artifacts)
      end
    end

    test "fails on invalid WWW-Authenticate header format (timestamp hash)", %{artifacts: artifacts, credentials: credentials}  do
      assert_raise Hawk.InternalServerError, "Invalid server timestamp hash", fn ->
        Client.authenticate([{'www-authenticate', 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"'}], credentials, artifacts)
      end
    end

    test "skips tsm validation when missing ts", %{artifacts: artifacts, credentials: credentials} do
      assert Client.authenticate([{'www-authenticate', 'Hawk error="Stale timestamp"'}], credentials, artifacts) == %{"www-authenticate" => %{error: "Stale timestamp"}}
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
