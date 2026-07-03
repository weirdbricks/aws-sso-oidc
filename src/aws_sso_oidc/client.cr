require "http/client"
require "json"

module AwsSsoOidc
  # Performs the AWS SSO OIDC device-authorization (RFC 8628) flow:
  # RegisterClient -> StartDeviceAuthorization -> poll CreateToken.
  class Client
    DEFAULT_SCOPES = ["sso:account:access"]

    def initialize(@region : String, @client_name : String = "aws-sso-oidc", @scopes : Array(String) = DEFAULT_SCOPES)
    end

    def oidc_base_url : String
      "https://oidc.#{@region}.amazonaws.com"
    end

    def register_client : Registration
      body = {
        "clientName" => @client_name,
        "clientType" => "public",
        "scopes"     => @scopes,
      }.to_json

      response = post_json("#{oidc_base_url}/client/register", body)

      unless response.status.success?
        raise "RegisterClient failed: #{response.status_code} #{response.body}"
      end

      json = JSON.parse(response.body)
      Registration.new(
        client_id: json["clientId"].as_s,
        client_secret: json["clientSecret"].as_s,
        client_id_issued_at: json["clientIdIssuedAt"].as_i64,
        client_secret_expires_at: json["clientSecretExpiresAt"].as_i64,
      )
    end

    def start_device_authorization(registration : Registration, start_url : String) : DeviceAuthorization
      body = {
        "clientId"     => registration.client_id,
        "clientSecret" => registration.client_secret,
        "startUrl"     => start_url,
      }.to_json

      response = post_json("#{oidc_base_url}/device_authorization", body)

      unless response.status.success?
        raise "StartDeviceAuthorization failed: #{response.status_code} #{response.body}"
      end

      json = JSON.parse(response.body)
      DeviceAuthorization.new(
        device_code: json["deviceCode"].as_s,
        user_code: json["userCode"].as_s,
        verification_uri: json["verificationUri"].as_s,
        verification_uri_complete: json["verificationUriComplete"].as_s,
        expires_in: json["expiresIn"].as_i,
        interval: json["interval"]?.try(&.as_i) || 5,
      )
    end

    # Polls CreateToken until the user approves, denies, or the device code expires.
    # Blocks the calling fiber for the duration of the wait.
    def poll_for_token(registration : Registration, device_auth : DeviceAuthorization) : TokenResult
      body_json = {
        "clientId"     => registration.client_id,
        "clientSecret" => registration.client_secret,
        "grantType"    => "urn:ietf:params:oauth:grant-type:device_code",
        "deviceCode"   => device_auth.device_code,
      }.to_json

      interval = device_auth.interval
      deadline = Time.utc + device_auth.expires_in.seconds

      loop do
        if Time.utc >= deadline
          raise DeviceAuthorizationExpired.new("device authorization expired before approval")
        end

        begin
          response = post_json("#{oidc_base_url}/token", body_json)

          if response.status.success?
            json = JSON.parse(response.body)
            return TokenResult.new(
              access_token: json["accessToken"].as_s,
              expires_in: json["expiresIn"].as_i,
              refresh_token: json["refreshToken"]?.try(&.as_s?),
            )
          end

          error = JSON.parse(response.body)["error"]?.try(&.as_s?) || ""
          case error
          when "authorization_pending"
            # keep polling at the same interval
          when "slow_down"
            interval += 5
          when "expired_token", "invalid_grant"
            raise DeviceAuthorizationExpired.new("device code expired or invalid (AWS-reported: #{error})")
          when "access_denied"
            raise DeviceAuthorizationDenied.new("user denied the authorization request")
          else
            raise "CreateToken failed: #{response.status_code} #{response.body}"
          end
        rescue ex : IO::TimeoutError | IO::Error | Socket::Error
          # Transient network hiccup; the deadline check above still bounds the loop.
        end

        sleep interval.seconds
      end
    end

    def refresh_access_token(registration : Registration, refresh_token : String) : TokenResult
      body = {
        "clientId"     => registration.client_id,
        "clientSecret" => registration.client_secret,
        "grantType"    => "refresh_token",
        "refreshToken" => refresh_token,
      }.to_json

      response = post_json("#{oidc_base_url}/token", body)

      unless response.status.success?
        raise "CreateToken (refresh) failed: #{response.status_code} #{response.body}"
      end

      json = JSON.parse(response.body)
      TokenResult.new(
        access_token: json["accessToken"].as_s,
        expires_in: json["expiresIn"].as_i,
        refresh_token: json["refreshToken"]?.try(&.as_s?),
      )
    end

    private def post_json(url : String, body : String) : HTTP::Client::Response
      uri = URI.parse(url)
      client = HTTP::Client.new(uri)
      client.connect_timeout = 10.seconds
      client.read_timeout = 15.seconds
      begin
        client.post(uri.request_target, headers: HTTP::Headers{"Content-Type" => "application/json"}, body: body)
      ensure
        client.close
      end
    end
  end
end
