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
defmodule Myapp do
  def request_and_authenticate(uri \\\\ "example.com") do
    my_credentials  = %{algorithm: :sha256, id: "dh37fgj492je", key: "aoijedoaijsdlaksjdl"}
    %{header: header, artifacts: artifacts} = Hawk.Client.header(uri, :get, my_credentials)


    case :httpc.request(:get, {[uri], [{'authorization', [header]}]}) do
      {:error, reason} ->
        {:error, reason}

      {:ok, {_status_line, headers, _body}}  ->
        Hawk.Client.authenticate(headers, my_credentials, artifacts)
    end
  end
end
```

### Plug

```elixir
defmodule Myapp.Router do
...
  pipeline :hawk do
    plug Plug.Hawk, credentials_fn: &Mypp.Accounts.get_credential!/1
  end
...
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
