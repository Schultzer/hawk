defmodule HawkRequestTest do
  use ExUnit.Case
  use Plug.Test
  alias Hawk.Request

  setup do
    Application.put_env(:plug, :validate_header_keys_during_test, true)
    [conn: conn(:post, "/resource/4?filter=a")
           |> put_req_header("content-type", "text/plain;x=")
           |> put_req_header("host", "example.com")]
  end

  describe "parse_host/2" do
    test "returns port 80 for non tls node request", %{conn: conn} do
      assert {:ok, %{host: "example.com", port: 80}} == Request.parse_host(conn, host_header_name: "host")
    end

    test "returns port 443 for non tls node request", %{conn: conn} do
      assert {:ok, %{host: "example.com", port: 443}} == Request.parse_host(%{conn | scheme: :https, port: 443}, host_header_name: "host")
    end

    test "returns port 443 for non tls node request (IPv6)", %{conn: conn} do
      conn = %{conn | scheme: :https, port: 443} |> put_req_header("host", "[123:123:123]")
      assert {:ok, %{host: "[123:123:123]", port: 443}} == Request.parse_host(conn, host_header_name: "host")
    end

    test "parses IPv6 headers", %{conn: conn} do
      conn = %{conn | scheme: :https, port: 443} |> put_req_header("host", "[123:123:123]:8000")
      assert {:ok, %{host: "[123:123:123]", port: 8000}} == Request.parse_host(conn, host_header_name: "host")
    end

    test "errors on header too long", %{conn: conn} do
      assert {:error, {500, "Invalid host header"}} == conn
                                                       |> put_req_header("host", (for _ <- 1..5000, into: <<>>, do: "x"))
                                                       |> Request.parse_host(host_header_name: "host")
    end
  end
end
