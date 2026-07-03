require "digest/sha1"
require "file_utils"

module AwsSsoOidc
  # Reads/writes ~/.aws/sso/cache/<sha1>.json in the exact format botocore
  # expects, so credentials obtained here are usable by the real `aws` CLI
  # (and vice versa).
  module TokenCache
    def self.cache_dir : String
      Path["~/.aws/sso/cache"].expand(home: true).to_s
    end

    # Matches botocore's SSOTokenLoader#_generate_cache_key: sha1(session_name)
    # if using an sso_session, else sha1(start_url) for legacy profiles.
    def self.cache_key(start_url : String, session_name : String?) : String
      Digest::SHA1.hexdigest(session_name || start_url)
    end

    def self.rfc3339_z(time : Time) : String
      time.to_utc.to_s("%Y-%m-%dT%H:%M:%SZ")
    end

    def self.write(start_url : String, region : String, session_name : String?, registration : Registration, token : TokenResult) : String
      cache_entry = {
        "startUrl"              => start_url,
        "region"                => region,
        "accessToken"           => token.access_token,
        "expiresAt"             => rfc3339_z(Time.utc + token.expires_in.seconds),
        "clientId"              => registration.client_id,
        "clientSecret"          => registration.client_secret,
        "registrationExpiresAt" => rfc3339_z(Time.unix(registration.client_secret_expires_at)),
      } of String => String
      if refresh_token = token.refresh_token
        cache_entry["refreshToken"] = refresh_token
      end

      FileUtils.mkdir_p(cache_dir)
      path = File.join(cache_dir, "#{cache_key(start_url, session_name)}.json")
      File.write(path, cache_entry.to_json)
      File.chmod(path, 0o600)
      path
    end
  end
end
