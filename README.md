# Hawk
[![CircleCI](https://circleci.com/gh/Schultzer/hawk.svg?style=svg)](https://circleci.com/gh/Schultzer/hawk)

"HTTP Holder-Of-Key Authentication Scheme.
Hawk is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification." - [hawk](https://github.com/hueniverse/hawk)

## Installation

```elixir
def deps do
  [{:hawk, "~> 0.1.0"}]
end
```

## Examples

### Client

```elixir
defmodule Myapp.Hawk do
  def request_and_authenticate(uri, credentials) do
    result = Hawk.Client.header(uri, :get, credentials)

    case :httpc.request(:get, {[uri], [{'authorization', [result.header]}]}) do
      {:error, reason} ->
        {:error, reason}

      {:ok, {_status_line, headers, _body}}  ->
        Hawk.Client.authenticate(headers, result)
    end
  end
end
```

### Server with plug

```elixir
defmodule Myapp.Hawk.Config do
  use Hawk.Config

  def get_credentials(id) do
    case MyRepo.get_by(Crendentials, id: id) do
      crendentials when is_map(crendentials) -> crendentials

      _ -> nil
    end
  end
end

defmodule Myapp.Hawk do
  @behaviour Plug

  def init(opts) do
    opts
  end

  def call(conn, opts) do
    conn
    |> Hawk.Request.new()
    |> Hawk.Server.authenticate(Myapp.Hawk.Config)
    |> case do
         {:ok, result} ->
           conn
           |> Plug.Conn.put_resp_header("server-authorization", Hawk.Server.header(result))
           |> Plug.Conn.put_status(200)

         {:error, {status, msg, {header, value}}} ->
           conn
           |> Plug.Conn.put_resp_header(header, value)
           |> Plug.Conn.resp(status, msg)
           |> Plug.Conn.halt()

         {:error, {status, msg}} ->
           conn
           |> Plug.Conn.resp(status, msg)
           |> Plug.Conn.halt()
       end
  end
end
```

### SNTP
Time sync management are done with [SNTP](https://github.com/Schultzer/sntp). add the retreiver to automatically sync the clock. the defualt is the machine time.

#### Application
```elixir
defmodule Myapp.Application do
...
    children = [
      worker(SNTP.Retriever, []),
    ]
...
end
```

#### Config
```elixir
config :sntp, auto_start: true
```

## Documentation

[hex documentation for hawk](https://hexdocs.pm/hawk)


## LICENSE

(The MIT License)

Copyright (c) 2018 Benjamin Schultzer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
