require "spec"
require "../src/aws_sso_oidc"

describe AwsSsoOidc::TokenCache do
  describe ".cache_key" do
    it "hashes the start_url for legacy (non-session) profiles" do
      start_url = "https://d-9a67576787.awsapps.com/start"
      AwsSsoOidc::TokenCache.cache_key(start_url, nil).should eq(
        Digest::SHA1.hexdigest(start_url)
      )
    end

    it "hashes the session_name when using an sso_session profile" do
      start_url = "https://d-9a67576787.awsapps.com/start"
      session_name = "my-session"
      AwsSsoOidc::TokenCache.cache_key(start_url, session_name).should eq(
        Digest::SHA1.hexdigest(session_name)
      )
    end
  end

  describe ".rfc3339_z" do
    it "formats as Z-suffixed RFC3339 matching botocore's serializer" do
      time = Time.utc(2026, 7, 3, 14, 27, 14)
      AwsSsoOidc::TokenCache.rfc3339_z(time).should eq("2026-07-03T14:27:14Z")
    end
  end

  describe ".write" do
    it "writes 0600-permissioned JSON with the expected fields" do
      Dir.mkdir_p(File.tempname)
      tmp_home = File.tempname
      Dir.mkdir_p(tmp_home)
      old_home = ENV["HOME"]?
      ENV["HOME"] = tmp_home

      begin
        registration = AwsSsoOidc::Registration.new(
          client_id: "client-id",
          client_secret: "client-secret",
          client_id_issued_at: Time.utc.to_unix,
          client_secret_expires_at: (Time.utc + 90.days).to_unix,
        )
        token = AwsSsoOidc::TokenResult.new(
          access_token: "access-token",
          expires_in: 3600,
          refresh_token: "refresh-token",
        )

        path = AwsSsoOidc::TokenCache.write(
          "https://d-example.awsapps.com/start", "us-east-2", nil, registration, token
        )

        File.exists?(path).should be_true
        File.info(path).permissions.value.should eq(0o600)

        contents = JSON.parse(File.read(path))
        contents["startUrl"].as_s.should eq("https://d-example.awsapps.com/start")
        contents["region"].as_s.should eq("us-east-2")
        contents["accessToken"].as_s.should eq("access-token")
        contents["clientId"].as_s.should eq("client-id")
        contents["clientSecret"].as_s.should eq("client-secret")
        contents["refreshToken"].as_s.should eq("refresh-token")
        contents["expiresAt"].as_s.should match(/\dZ$/)
        contents["registrationExpiresAt"].as_s.should match(/\dZ$/)
      ensure
        ENV["HOME"] = old_home
        FileUtils.rm_rf(tmp_home)
      end
    end
  end
end
