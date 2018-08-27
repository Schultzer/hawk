defmodule HawkTest do
  use ExUnit.Case
  alias Hawk.{Client, Server}

  defmodule Config do
    use Hawk.Config

    def get_credentials(id, _opts) do
      %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"}
    end
  end

  setup do
    [
      request: %{method: "GET", url: "/resource/4?filter=a", host: "example.com", port: 8080}
    ]
  end

  test "generates a header then successfully parse it (configuration)", %{request: request} do
    assert %{header: header} = Client.header(URI.parse("http://example.com:8080/resource/4?filter=a"), :get, Config.get_credentials("123456"), ext: "some-app-data")
    assert {:ok, %{credentials: credentials, artifacts: artifacts}} = Server.authenticate(Map.merge(request, %{authorization: header}), Config)
    assert credentials.user == "steve"
    assert artifacts.ext == "some-app-data"
  end

  test "generates a header then successfully parse it request", %{request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, Config.get_credentials("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    assert {:ok, %{credentials: credentials, artifacts: artifacts} = result} = Hawk.Server.authenticate(Map.merge(request, %{method: "POST", authorization: header, content_type: content_type}), Config)
    assert credentials.user == "steve"
    assert artifacts.ext == "some-app-data"
    assert {:ok, result} == Hawk.Server.authenticate_payload(payload, result, content_type)

    server_authorization = Hawk.Server.header(result, payload: "some reply", content_type: "text/plain", ext: "response-specific")
    assert {:ok, header} = Hawk.Header.parse(server_authorization)
    assert {:ok, %{"server-authorization" => header}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], result, %{payload: "some reply"})
  end

  test "generates a header then successfully parse it (absolute request uri)", %{request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, Config.get_credentials("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    assert {:ok, %{credentials: credentials, artifacts: artifacts} = result} = Hawk.Server.authenticate(Map.merge(request, %{method: "POST", authorization: header, content_type: content_type}), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert {:ok, result} == Hawk.Server.authenticate_payload(payload, result, content_type)

    server_authorization = Hawk.Server.header(result,  payload: "some reply", content_type: "text/plain", ext: "response-specific")
    assert {:ok, header} = Hawk.Header.parse(server_authorization)
    assert {:ok, %{"server-authorization" => header}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], result, %{payload: "some reply"})
  end

  test "generates a header then successfully parse it (no server header options)", %{request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, Config.get_credentials("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    assert {:ok, %{credentials: credentials, artifacts: artifacts} = result} = Hawk.Server.authenticate(Map.merge(request, %{method: "POST", authorization: header, content_type: content_type}), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert {:ok, result} == Hawk.Server.authenticate_payload(payload, result, content_type)

    server_authorization = Hawk.Server.header(result)
    assert {:ok, header} = Hawk.Header.parse(server_authorization)
    assert {:ok, %{"server-authorization" => header}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], result)
  end

  test "generates a header then fails to parse it (missing server header hash)", %{request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, Config.get_credentials("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    assert {:ok, %{credentials: credentials, artifacts: artifacts} = result} = Hawk.Server.authenticate(Map.merge(request, %{authorization: header, method: "POST", content_type: content_type}), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert {:ok, result} == Hawk.Server.authenticate_payload(payload, result, content_type)
    server_authorization = Hawk.Server.header(result)
    assert {:error, {500, "Missing response hash attribute"}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], result, payload: "some reply")
  end

  test "generates a header then successfully parse it (with hash)", %{request: request} do
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), payload: "hola!", ext: "some-app-data")
    assert {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
  end

  test "generates a header then successfully parse it then validate payload", %{request: request} do
    assert  %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), payload: "hola!", ext: "some-app-data")
    assert {:ok, %{credentials: credentials, artifacts: artifacts} = result} = Hawk.Server.authenticate(Map.put(request, :authorization, header), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert {:ok, result} == Hawk.Server.authenticate_payload("hola!", result, "")
    assert {:error, {401, "Bad payload hash", {"www-authenticate", "Hawk error=\"Bad payload hash\""}}} == Hawk.Server.authenticate_payload("hello!", result, "")
  end

  test "generates a header then successfully parses and validates payload", %{request: request} do
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), payload: "hola!", ext: "some-app-data")
    assert {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
  end

  test "generates a header then successfully parse it (app)", %{request: request} do
    assert  %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), ext: "some-app-data", app: "asd23ased")
    assert {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert artifacts[:app] == "asd23ased"
  end

  test "generates a header then successfully parse it (app, dlg)", %{request: request} do
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), ext: "some-app-data", app: "asd23ased", dlg: "23434szr3q4d")
    assert {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), Config)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert artifacts[:app] == "asd23ased"
    assert artifacts[:dlg] == "23434szr3q4d"
  end

  test "generates a header then fail authentication due to bad hash", %{request: request} do
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), payload: "hola!", ext: "some-app-data")
    assert {:error, {401, "Bad payload hash", {"www-authenticate", "Hawk error=\"Bad payload hash\""}}} == Hawk.Server.authenticate(Map.put(request, :authorization, header), Config, %{payload: "byebye!"})
  end

  test "generates a header for one resource then fail to authenticate another", %{request: request} do
    assert %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, Config.get_credentials("123456"), ext: "some-app-data")
    assert {:error, {401, "Bad mac", {"www-authenticate", "Hawk error=\"Bad mac\""}}} == Hawk.Server.authenticate(Map.merge(request, %{authorization: header, url: "/something/else"}), Config)
  end
end
