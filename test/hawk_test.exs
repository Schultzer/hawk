defmodule HawkTest do
  use ExUnit.Case
  alias Hawk.{Client, Server}

  setup do
    [
      credentials_fn: fn id -> %{id: id, key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: (if id == "1", do: :sha, else: :sha256), user: "steve"} end,
      request: %{method: "GET", url: "/resource/4?filter=a", host: "example.com", port: 8080}
    ]
  end

  test "generates a header then successfully parse it (configuration)", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Client.header(URI.parse("http://example.com:8080/resource/4?filter=a"), :get, credentials_fn.("123456"), ext: "some-app-data")
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Server.authenticate(Map.merge(request, %{authorization: header}), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts.ext == "some-app-data"
  end

  test "generates a header then successfully parse it request", %{credentials_fn: credentials_fn, request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, credentials_fn.("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.merge(request, %{method: "POST", authorization: header, content_type: content_type}), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts.ext == "some-app-data"
    assert Map.keys(Hawk.Server.authenticate_payload(payload, credentials, artifacts, content_type)) == [:artifacts, :credentials]

    server_authorization = Hawk.Server.header(credentials, artifacts, payload: "some reply", content_type: "text/plain", ext: "response-specific")
    {:ok, header} = Hawk.Header.parse(server_authorization)
    assert {:ok, %{"server-authorization" => header}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], credentials, artifacts, %{payload: "some reply"})
  end

  test "generates a header then successfully parse it (absolute request uri)", %{credentials_fn: credentials_fn, request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, credentials_fn.("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.merge(request, %{method: "POST", authorization: header, content_type: content_type}), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert Map.keys(Hawk.Server.authenticate_payload(payload, credentials, artifacts, content_type)) == [:artifacts, :credentials]

    server_authorization = Hawk.Server.header(credentials, artifacts,  payload: "some reply", content_type: "text/plain", ext: "response-specific")
    {:ok, header} = Hawk.Header.parse(server_authorization)
    assert {:ok, %{"server-authorization" => header}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], credentials, artifacts, %{payload: "some reply"})
  end

  test "generates a header then successfully parse it (no server header options)", %{credentials_fn: credentials_fn, request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, credentials_fn.("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.merge(request, %{method: "POST", authorization: header, content_type: content_type}), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert Map.keys(Hawk.Server.authenticate_payload(payload, credentials, artifacts, content_type)) == [:artifacts, :credentials]

    server_authorization = Hawk.Server.header(credentials, artifacts)
    {:ok, header} = Hawk.Header.parse(server_authorization)
    assert {:ok, %{"server-authorization" => header}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], credentials, artifacts)
  end

  test "generates a header then fails to parse it (missing server header hash)", %{credentials_fn: credentials_fn, request: request} do
    content_type = "text/plain;x=y"
    payload = "some not so random text"
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :post, credentials_fn.("123456"), ext: "some-app-data", payload: payload, content_type: content_type)
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.merge(request, %{authorization: header, method: "POST", content_type: content_type}), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert Map.keys(Hawk.Server.authenticate_payload(payload, credentials, artifacts, content_type)) == [:artifacts, :credentials]
    server_authorization = Hawk.Server.header(credentials, artifacts)
    assert {:error, {500, "Missing response hash attribute"}} == Hawk.Client.authenticate([{'content-type', 'text/plain'}, {'server-authorization', '#{server_authorization}'}], credentials, artifacts, payload: "some reply")
  end

  test "generates a header then successfully parse it (with hash)", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), payload: "hola!", ext: "some-app-data")
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
  end

  test "generates a header then successfully parse it then validate payload", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), payload: "hola!", ext: "some-app-data")
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert Map.keys(Hawk.Server.authenticate_payload("hola!", credentials, artifacts, "")) == [:artifacts, :credentials]
    assert {:error, {401, "Bad payload hash", {"www-authenticate", "Hawk error=\"Bad payload hash\""}}} == Hawk.Server.authenticate_payload("hello!", credentials, artifacts, "")
  end

  test "generates a header then successfully parses and validates payload", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), payload: "hola!", ext: "some-app-data")
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
  end

  test "generates a header then successfully parse it (app)", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), ext: "some-app-data", app: "asd23ased")
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert artifacts[:app] == "asd23ased"
  end

  test "generates a header then successfully parse it (app, dlg)", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), ext: "some-app-data", app: "asd23ased", dlg: "23434szr3q4d")
    {:ok, %{credentials: credentials, artifacts: artifacts}} = Hawk.Server.authenticate(Map.put(request, :authorization, header), credentials_fn)
    assert credentials.user == "steve"
    assert artifacts[:ext] == "some-app-data"
    assert artifacts[:app] == "asd23ased"
    assert artifacts[:dlg] == "23434szr3q4d"
  end

  test "generates a header then fail authentication due to bad hash", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), payload: "hola!", ext: "some-app-data")
    assert {:error, {401, "Bad payload hash", {"www-authenticate", "Hawk error=\"Bad payload hash\""}}} == Hawk.Server.authenticate(Map.put(request, :authorization, header), credentials_fn, %{payload: "byebye!"})
  end

  test "generates a header for one resource then fail to authenticate another", %{credentials_fn: credentials_fn, request: request} do
    %{header: header} = Hawk.Client.header("http://example.com:8080/resource/4?filter=a", :get, credentials_fn.("123456"), ext: "some-app-data")
    assert {:error, {401, "Bad mac", {"www-authenticate", "Hawk error=\"Bad mac\""}}} == Hawk.Server.authenticate(Map.merge(request, %{authorization: header, url: "/something/else"}), credentials_fn)
  end
end
