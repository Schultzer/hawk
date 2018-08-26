defmodule HawkRequestTest do
  use ExUnit.Case
  alias Hawk.Request

  setup do
    [req: %{method: "GET", scheme: :http, request_path: "/resource/4", query_string: "filter=a", host: "example.com", port: 80, req_headers: %{"content-type" => "text/plain;x=", "host" => "example.com"}}]
  end

  describe "parse_host/2" do
    test "returns port 80 for non tls node request", %{req: req} do
      assert {:ok, %{host: "example.com", port: 80}} == Request.parse_host(req, host_header_name: "host")
    end

    test "returns port 443 for non tls node request", %{req: req} do
      assert {:ok, %{host: "example.com", port: 443}} == Request.parse_host(%{req | scheme: :https, port: 443}, host_header_name: "host")
    end

    test "returns port 443 for non tls node request (IPv6)", %{req: %{req_headers: headers} = req} do
      req = %{req | scheme: :https, port: 443, req_headers: %{headers | "host" => "[123:123:123]"}}
      assert {:ok, %{host: "[123:123:123]", port: 443}} == Request.parse_host(req, host_header_name: "host")
    end

    test "parses IPv6 headers", %{req: %{req_headers: headers} = req} do
      req = %{req | scheme: :https, port: 443, req_headers: %{headers | "host" => "[123:123:123]:8000"}}
      assert {:ok, %{host: "[123:123:123]", port: 8000}} == Request.parse_host(req, host_header_name: "host")
    end

    test "errors on header too long", %{req: %{req_headers: headers} = req} do
      req = %{req | req_headers: %{headers | "host" => (for _ <- 1..5000, into: <<>>, do: "x")}}
      assert {:error, {500, "Invalid host header"}} == Request.parse_host(req, host_header_name: "host")
    end
  end
  describe "new/2" do
    test "should fail on invalid host header", %{req: %{req_headers: headers} = req} do
      req = %{req | query_string: "bewit=MTIzNDU2XDQ1MDk5OTE3MTlcTUE2eWkwRWRwR0pEcWRwb0JkYVdvVDJrL0hDSzA1T0Y3MkhuZlVmVy96Zz1cc29tZS1hcHAtZGF0YQa", req_headers: %{headers | "host" => "example.com:something"}}
      assert {:error, {500, "Invalid host header"}} == Hawk.Request.new(req)
    end

    test "errors on an bad host header (pad port)", %{req: %{req_headers: headers} = req} do
      req = %{req | req_headers: Map.merge(headers, %{"host" => "example.com:something", "authorization" => "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""})}
      assert {:error, {500, "Invalid host header"}} == Hawk.Request.new(req)
    end

    test "errors on an bad host header (missing host)", %{req: %{req_headers: headers} = req} do
      req = %{req | req_headers: Map.merge(headers, %{"host" => ":8080", "authorization" => "Hawk id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\""})}
      assert {:error, {500, "Invalid host header"}} == Hawk.Request.new(req)
    end

    test "parses a valid authentication header (host override)", %{req: %{req_headers: headers} = req} do
      req = %{req | req_headers: Map.merge(headers, %{"host" => "example1.com:8080", "authorization" => "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\""})}
      assert %{host: "example.com"} = Hawk.Request.new(req, host: "example.com")
    end
  end
end
