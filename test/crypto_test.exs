defmodule HawkCryptoTest do
  use ExUnit.Case
  alias Hawk.Crypto

  describe "generate_normalized_string/2" do
    test "return a valid normalized string" do
      artifacts = %{host: "example.com", method: "GET", nonce: "k3k4j5", port: 8080, resource: "/resource/something", ts: 1357747017}
      assert Crypto.generate_normalized_string("header", artifacts) == "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n"
    end

    test "return a valid normalized string with ext" do
      artifacts = %{ext: "this is some app data", host: "example.com", method: "GET", nonce: "k3k4j5", port: 8080, resource: "/resource/something", ts: 1357747017 }
      assert Crypto.generate_normalized_string("header", artifacts) == "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some app data\n"
    end

    test "return a valid normalized string with ext and payload" do
      artifacts = %{ext: "this is some app data", hash: "U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=", host: "example.com", method: "GET", nonce: "k3k4j5", port: 8080, resource: "/resource/something", ts: 1357747017}
      assert Crypto.generate_normalized_string("header", artifacts) == "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some app data\n"
    end
  end
end
