require "../src/aws_sso_oidc"

region       = ARGV[0]? || "us-east-2"
start_url    = ARGV[1]? || abort("usage: aws_sso_oidc_login <region> <start_url> [session_name]")
session_name = ARGV[2]?

client = AwsSsoOidc::Client.new(region)

puts "Registering client against #{client.oidc_base_url} ..."
registration = client.register_client
puts "clientId:               #{registration.client_id}"
puts "clientSecret:            #{registration.client_secret[0, 12]}... (truncated)"
puts "clientIdIssuedAt:        #{Time.unix(registration.client_id_issued_at)}"
puts "clientSecretExpiresAt:   #{Time.unix(registration.client_secret_expires_at)}"

puts
puts "Starting device authorization for #{start_url} ..."
device_auth = client.start_device_authorization(registration, start_url)
puts "userCode:                #{device_auth.user_code}"
puts "verificationUri:         #{device_auth.verification_uri}"
puts "verificationUriComplete: #{device_auth.verification_uri_complete}"
puts "expiresIn:               #{device_auth.expires_in}s"
puts "interval:                #{device_auth.interval}s"
puts
puts "If the browser does not open, open the following URL:"
puts device_auth.verification_uri_complete
if ENV["NO_AUTO_OPEN"]?
  puts "(NO_AUTO_OPEN set; not auto-opening browser)"
else
  AwsSsoOidc.open_browser(device_auth.verification_uri_complete)
end

puts
puts "Waiting for approval..."
begin
  token = client.poll_for_token(registration, device_auth)
  puts "Success!"
  puts "accessToken:  #{token.access_token[0, 20]}... (truncated)"
  puts "expiresIn:    #{token.expires_in}s"
  puts "refreshToken: #{token.refresh_token.try(&.[0, 20]) || "(none)"}#{token.refresh_token ? "... (truncated)" : ""}"

  cache_path = AwsSsoOidc::TokenCache.write(start_url, region, session_name, registration, token)
  puts
  puts "Wrote token cache: #{cache_path}"
  puts "  cache key basis: #{session_name || start_url} (#{session_name ? "session_name" : "start_url"})"
  puts "  permissions: #{File.info(cache_path).permissions}"

  if refresh_token = token.refresh_token
    puts
    puts "Testing refresh-token exchange (no browser round-trip)..."
    refreshed = client.refresh_access_token(registration, refresh_token)
    puts "Success!"
    puts "new accessToken:  #{refreshed.access_token[0, 20]}... (truncated)"
    puts "new expiresIn:    #{refreshed.expires_in}s"
    puts "new refreshToken: #{refreshed.refresh_token.try(&.[0, 20]) || "(none)"}#{refreshed.refresh_token ? "... (truncated)" : ""}"

    cache_path = AwsSsoOidc::TokenCache.write(start_url, region, session_name, registration, refreshed)
    puts "Re-wrote token cache: #{cache_path}"
  else
    puts
    puts "No refreshToken returned; skipping refresh-token test."
  end
rescue ex : AwsSsoOidc::DeviceAuthorizationExpired
  STDERR.puts "Error: #{ex.message}"
  exit 1
rescue ex : AwsSsoOidc::DeviceAuthorizationDenied
  STDERR.puts "Error: #{ex.message}"
  exit 1
end
