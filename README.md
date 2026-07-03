# aws-sso-oidc

Native Crystal implementation of the AWS SSO OIDC device-authorization flow
(RFC 8628) — the same flow behind `aws sso login`. Writes/reads
`~/.aws/sso/cache/*.json` in the exact format botocore uses, so tokens are
interoperable with the real `aws` CLI in both directions.

## Install

Add to `shard.yml`:

```yaml
dependencies:
  aws-sso-oidc:
    github: weirdbricks/aws-sso-oidc
```

Then:

```
shards install
```

## Library usage

```crystal
require "aws-sso-oidc"

client = AwsSsoOidc::Client.new("us-east-2")

registration = client.register_client
device_auth = client.start_device_authorization(registration, "https://d-xxxxxxxxxx.awsapps.com/start")

puts "Open #{device_auth.verification_uri_complete} to approve"
AwsSsoOidc.open_browser(device_auth.verification_uri_complete)

token = client.poll_for_token(registration, device_auth)

AwsSsoOidc::TokenCache.write(
  "https://d-xxxxxxxxxx.awsapps.com/start", "us-east-2", nil, registration, token
)
```

`poll_for_token` blocks until the user approves/denies or the device code
expires, raising `AwsSsoOidc::DeviceAuthorizationDenied` or
`AwsSsoOidc::DeviceAuthorizationExpired` respectively.

To refresh an access token without a browser round-trip (requires a
`refreshToken`, which AWS only issues when registration includes scopes —
`Client` requests `sso:account:access` by default):

```crystal
refreshed = client.refresh_access_token(registration, token.refresh_token.not_nil!)
```

## CLI

```
shards build
./bin/aws_sso_oidc_login <region> <start_url> [session_name]
```

Example:

```
./bin/aws_sso_oidc_login us-east-2 https://d-9a67576787.awsapps.com/start
```

Registers a client, prints a verification URL, opens it in your browser,
polls until approved, writes the token cache, and (if a refresh token was
issued) exercises the refresh exchange. Set `NO_AUTO_OPEN=1` to skip opening
the browser automatically.

Once a cache is written, the real `aws` CLI reads it directly:

```
aws sts get-caller-identity --profile <profile-pointing-at-that-start-url>
```
