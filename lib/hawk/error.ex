defmodule Hawk.Error do
  @moduledoc false

  @spec parse(atom()) :: 400 | 401 | 500

  for error <- ~w(bad_header_format header_length_too_long invalid_header_syntax invalid_host_header)a do
    def parse(unquote(error)), do: 400
  end

  for error <- ~w(access_expired bad_mac bad_message_hash bad_payload_hash empty_bewit missing_required_payload_hash invalid_method
                  invalid_nonce stale_timestamp unauthorized unauthorized_hawk unknown_credentials)a do
    def parse(unquote(error)), do: 401
  end

  for error <- ~w(bad_response_mac bad_response_payload_mac invalid_argument_type invalid_bewit_encoding invalid_bewit_structure
                  invalid_credentials invalid_inputs invalid_server_timestamp_hash missing_bewit_attributes multiple_authentications
                  missing_attributes missing_response_hash_attribute server_authorization resource_path_exceeds_max_length
                  unknown_algorithm www_authenticate)a do
    def parse(unquote(error)), do: 500
  end

  def parse(_), do: 500
end
