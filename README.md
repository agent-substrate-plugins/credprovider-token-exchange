# token-exchange credential provider

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A [substrate](https://github.com/agent-substrate/substrate) credential provider
that exchanges an actor's Substrate-minted JWT for an access token at an
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token endpoint, such as
Google Cloud STS, the only endpoint supported so far. It implements substrate's `CredentialProvider` gRPC API
(`api/credprovider/v1`) for egress credential injection.

## How it works

For a credential URI naming a profile, the provider:

1. refuses the request unless the policy grants the profile to the actor's
   atespace;
2. mints the actor's JWT through ate-api-server's `Control.MintActorJwt`, with
   the profile's `audience` as its `aud`;
3. exchanges it at the profile's `tokenUrl` for an access token;
4. caches the token per (atespace, actor, profile) until its expiry minus
   max(lifetime/3, 30s), for at most an hour, or for 60s if the endpoint
   returned no `expires_in`, and returns it to the egress gateway.

## Credential URIs

```
ate-secret://<providerName>/token-exchange/<profile>
```

`<providerName>` is the config file's `providerName`. User information,
ports, queries, fragments and percent-encoding are refused.

## Configuration

`config/config-example.yaml` is a ConfigMap holding the profiles and the
atespace policy. The provider reads it only at startup, so restart the
Deployment after changing it.

| Field | Meaning |
| --- | --- |
| `providerName` | Host of the `ate-secret://` URIs the provider serves; a lowercase DNS-1123 subdomain |
| `profiles[].name` | Referenced from the credential URI and the policy |
| `profiles[].tokenUrl` | Must be `https://sts.googleapis.com/v1/token` |
| `profiles[].audience` | RFC 8693 `audience` and the minted actor JWT's `aud`: the workload identity pool provider's resource name |
| `profiles[].scopes` | RFC 8693 `scope`; at least one |
| `policy.atespaces` | Profiles each atespace may use; an atespace not listed gets none |

## Security model

- **Only the egress gateway may call.** The provider serves mutual TLS with a
  certificate from substrate's servicedns signer, and admits a caller only if
  its certificate chains to substrate's podidentity trust bundle and carries
  `--injector-identity`.
- **The provider holds ate-api-server's `egress_gateway` role.** That is the
  only role that can call `MintActorJwt`, and it also lets the provider list
  and get every actor and read every actor's egress policy, in every atespace.
- **Each atespace gets only the profiles its policy grants.** Requests for other
  profiles are refused with `PermissionDenied` before any JWT is minted.
- **Tokens outlive changes made after they're cached.** A cached token is
  served until its refresh time even if the token endpoint revokes the grant,
  or the actor is deleted and another is created with the same name.
- **The provider calls only Google Cloud STS.** It ignores `HTTP(S)_PROXY`,
  and `config/networkpolicy.yaml` allows egress only to ate-api-server, DNS
  and public addresses on port 443.
- **The token endpoint decides the rest.** What a token can reach is whatever
  the endpoint's issuer grants the actor's federated identity.

## Install

Prerequisites: substrate v1.0.0-rc.1 or later, and a registry for
`KO_DOCKER_REPO`. The Makefile runs [ko](https://ko.build) with `go run`.

1. **Trust the actor JWT issuer** at the token endpoint. Either let it reach
   ate-idp-server's discovery document at your `actorJWT.issuer`, or upload
   the key set from `<issuer>/openid/v1/jwks` where the endpoint supports
   that. Admit only actor tokens: their `sub` is `actor/<atespace>/<name>`.
   For Google Cloud Workload Identity Federation:

   ```bash
   curl -s "$ISSUER/openid/v1/jwks" > jwks.json   # drop this and --jwk-json-path if the issuer is public
   gcloud iam workload-identity-pools providers create-oidc PROVIDER \
     --project=PROJECT --location=global --workload-identity-pool=POOL \
     --issuer-uri="$ISSUER" \
     --jwk-json-path=jwks.json \
     --attribute-condition="assertion.sub.startsWith('actor/') && 'actor.ate.dev' in assertion" \
     --attribute-mapping="google.subject=assertion.sub.extract('actor/{actor}'),attribute.atespace=assertion['actor.ate.dev'].atespace"
   ```

   The mapping strips the `actor/` prefix because `google.subject` is limited
   to 127 bytes. Grant `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/subject/<atespace>/<name>`
   for one actor, or
   `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/attribute.atespace/<atespace>`
   for an atespace. The profile's `audience` is the provider's resource name,
   `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER`.
   With an uploaded key set, upload it again after each signing key is added
   or removed.
2. **Configure the provider.** Edit `config/config-example.yaml` and apply it.
3. **Deploy:** `KO_DOCKER_REPO=<registry> make deploy`.
4. **Let the provider mint actor JWTs.** Redeploy ate-api-server with the
   provider's SPIFFE ID added to the comma-separated egress gateway IDs,
   keeping any already there. `<record>` is the install record ate-setup
   wrote, `~/.cache/ate-setup/installs/<context>.yaml` by default; supply
   secrets such as database connection strings again, since the record
   leaves them out.

   ```bash
   ate-setup deploy apiserver --config <record> \
     --egress-gateway-extra-spiffe-ids=spiffe://cluster.local/ns/ate-system/sa/credprovider-token-exchange
   ```

5. **Point the egress gateway at the provider**, next to any existing
   provider:

   ```bash
   ate-setup deploy atenet --config <record> \
     --credential-provider='[{"name":"k8s.io"},{"name":"<providerName>","address":"credprovider-token-exchange.ate-system.svc:50051"}]'
   ```

**Uninstall.** Redeploy the gateway without the provider in
`--credential-provider` and ate-api-server without its SPIFFE ID in
`--egress-gateway-extra-spiffe-ids`, then run `make undeploy`. It leaves the
ConfigMap in place.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--listen-address` | `:50051` | gRPC listen address |
| `--health-address` | `:9090` | HTTP address for `/healthz` and `/readyz` |
| `--config` | required | Profiles and policy file |
| `--server-cred-bundle` | required | Serving credential bundle: PKCS#8 key and certificate chain |
| `--client-ca-file` | required | Trust bundle the caller's certificate must chain to |
| `--injector-identity` | required | SPIFFE ID of substrate's egress gateway, the only caller accepted |
| `--ateapi-address` | required | gRPC target of ate-api-server |
| `--ateapi-ca-file` | required | Trust bundle ate-api-server's certificate must chain to |
| `--ateapi-client-cert` | required | Credential bundle presented to ate-api-server |
| `--ateapi-server-name` | required | DNS name ate-api-server's certificate must carry |
| `--token-exchange-ca-file` | none | PEM certificates trusted for token endpoints, beside the system roots; read at startup |
| `--fetch-timeout` | `3s` | Time limit for minting and exchanging one token; keep it under the gateway's 4s credential injection timeout |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--drain-grace` | `5s` | How long in-flight calls may finish on shutdown |

`config/deployment.yaml` sets every required flag.

## Development

```bash
make test               # go test -race ./...
make verify             # gofmt, go vet, go mod tidy check
make fmt                # gofmt -w .
make release-manifest   # manifests with the image pinned by digest
make release-images     # VERSION=<tag> KO_DOCKER_REPO=<repo>: push the release image
```

Three packages are copies of substrate code kept in step by hand, since only
substrate's public `api/` and `pkg/` packages can be imported:
`internal/credbundle` of substrate's `internal/credbundle`, `internal/mtls` of
the server credentials in `cmd/credential-provider/kubernetes-secrets`, and
`internal/ateapiclient` of substrate's `internal/ateapiauth`.
