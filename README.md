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

Actor JWTs expire after 1 hour and Google Cloud STS tokens expire with them,
so in practice each token is cached for about 40 minutes.

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
| `profiles[].audience` | RFC 8693 `audience` and the minted actor JWT's `aud`: the workload identity pool provider's resource name, `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER` |
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
  served until its refresh time, about 40 minutes for Google Cloud STS, even
  if the token endpoint revokes the grant, or the actor is deleted and
  another is created with the same name.
- **The provider calls only Google Cloud STS.** It ignores `HTTP(S)_PROXY`,
  and `config/networkpolicy.yaml` allows egress only to ate-api-server, DNS
  and public addresses on port 443.
- **The token endpoint decides the rest.** What a token can reach is whatever
  the endpoint's issuer grants the actor's federated identity.

## Install

Prerequisites: substrate v1.0.0 or later, and a registry for
`KO_DOCKER_REPO`. The Makefile runs [ko](https://ko.build) with `go run`.
Releases ship no `ate-setup` binary, so steps 4 and 5 run it with
`go run ./cmd/ate-setup` from a substrate checkout at your installed version.

> [!WARNING]
> From a checkout, `deploy apiserver` and `deploy atenet` rebuild substrate's
> images and roll them out unless you pass `--image-repo` and `--image-tag`,
> such as `--image-repo=ghcr.io/agent-substrate/substrate --image-tag=<installed tag>`,
> or the record has `images.repo`.

1. **Trust the actor JWT issuer at Google Cloud** with Workload Identity
   Federation. Define the variables first:

   ```bash
   PROJECT=my-project      # Google Cloud project ID
   POOL=substrate-actors   # workload identity pool ID
   PROVIDER=my-cluster     # OIDC provider ID in that pool
   PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
   AUDIENCE="//iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER"
   ```

   Read the issuer and its key set from ate-idp-server through a
   port-forward, verifying its certificate against substrate's servicedns
   trust bundle:

   ```bash
   kubectl get clustertrustbundles -l podcert.ate.dev/canarying=live -o json \
     | jq -r '.items[] | select(.spec.signerName == "servicedns.podcert.ate.dev/identity") | .spec.trustBundle' \
     > idp-ca.crt
   kubectl -n ate-system port-forward svc/idp 8443:443 >/dev/null &
   PF_PID=$!
   IDP=(curl -fsS --cacert idp-ca.crt --resolve idp.ate-system.svc:8443:127.0.0.1)
   # Wait up to 30s for the port-forward; if it never comes up, the next command shows the error.
   "${IDP[@]}" --no-show-error --retry 30 --retry-delay 1 --retry-connrefused -o /dev/null https://idp.ate-system.svc:8443/.well-known/openid-configuration
   ISSUER="$("${IDP[@]}" https://idp.ate-system.svc:8443/.well-known/openid-configuration | jq -r .issuer)"
   "${IDP[@]}" https://idp.ate-system.svc:8443/openid/v1/jwks > jwks.json
   kill "$PF_PID"
   echo "$ISSUER"; jq '.keys | length' jwks.json   # the issuer, and at least 1 key
   ```

   Create the pool and an OIDC provider for the issuer:

   ```bash
   gcloud iam workload-identity-pools create "$POOL" \
     --project="$PROJECT" --location=global --display-name="Substrate actors"
   gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
     --project="$PROJECT" --location=global --workload-identity-pool="$POOL" \
     --issuer-uri="$ISSUER" \
     --jwk-json-path=jwks.json \
     --allowed-audiences="$AUDIENCE" \
     --attribute-condition="assertion.sub.startsWith('actor/') && 'actor.ate.dev' in assertion" \
     --attribute-mapping="google.subject=assertion.sub.extract('actor/{actor}'),attribute.atespace=assertion['actor.ate.dev'].atespace"
   ```

   The condition admits only actor tokens, whose `sub` is
   `actor/<atespace>/<name>`, and the mapping strips `actor/` to fit
   `google.subject`'s 127 bytes. Google Cloud can't reach the default
   in-cluster issuer, hence the uploaded key set. If your organization sets
   `constraints/iam.workloadIdentityPoolProviders`, its allowed values must
   include `$ISSUER`. After each signing key is added or removed, fetch
   `jwks.json` again as above and upload it:

   ```bash
   gcloud iam workload-identity-pools providers update-oidc "$PROVIDER" \
     --project="$PROJECT" --location=global --workload-identity-pool="$POOL" \
     --jwk-json-path=jwks.json
   ```

   Grant roles to one actor or to an atespace, not to the whole pool. STS
   returns a federated token, so use services that support direct resource
   access; the provider doesn't impersonate a service account. The examples
   grant on the project for brevity; prefer the resource, such as
   `gcloud storage buckets add-iam-policy-binding gs://BUCKET` with the same
   flags.

   ```bash
   # One actor, agent-1 in atespace team-a:
   gcloud projects add-iam-policy-binding "$PROJECT" --role=roles/storage.objectViewer \
     --member="principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/subject/team-a/agent-1"
   # Every actor in atespace team-a:
   gcloud projects add-iam-policy-binding "$PROJECT" --role=roles/storage.objectViewer \
     --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/attribute.atespace/team-a"
   ```

2. **Configure the provider.** Edit `config/config-example.yaml`: set each
   profile's `audience` to `$AUDIENCE` and grant profiles to atespaces. Then
   `kubectl apply -f config/config-example.yaml`.
3. **Deploy:** `KO_DOCKER_REPO=<registry> make deploy`. The cluster's nodes
   must be able to pull from `<registry>`.
4. **Let the provider mint actor JWTs.** Redeploy ate-api-server with the
   provider's SPIFFE ID added to the comma-separated egress gateway IDs,
   keeping any already there (`ateapi.authz.egressGatewayExtraSPIFFEIDs` in
   the record). `<record>` is the install record ate-setup
   wrote, `~/.cache/ate-setup/installs/<context>.yaml` by default; supply
   secrets such as database connection strings again, since the record
   leaves them out.

   ```bash
   go run ./cmd/ate-setup deploy apiserver --config <record> \
     --egress-gateway-extra-spiffe-ids=spiffe://cluster.local/ns/ate-system/sa/credprovider-token-exchange
   ```

5. **Point the egress gateway at the provider.** `--credential-provider`
   replaces the whole list, so include the providers in the record's
   `atenet.egress.credentialProvider`, such as the bundled `k8s.io`:

   ```bash
   go run ./cmd/ate-setup deploy atenet --config <record> \
     --credential-provider='[{"name":"k8s.io"},{"name":"<providerName>","address":"credprovider-token-exchange.ate-system.svc:50051"}]'
   ```

**Uninstall.** Redeploy the gateway without the provider in
`--credential-provider` and ate-api-server without its SPIFFE ID in
`--egress-gateway-extra-spiffe-ids`, then run `make undeploy`. It leaves the
ConfigMap in place.

## Using a profile

An actor's `EgressPolicy` asks for a profile's token in a `replaceHeaders`
effect on an `https` rule. For the example config, whose `providerName` is
`sts` and whose profile is `gcp`:

```yaml
rules:
- https:
    hostnames: ["storage.googleapis.com"]
    effects:
      replaceHeaders:
      - header: Authorization
        prefix: "Bearer "
        credentialUri: ate-secret://sts/token-exchange/gcp
```

Keep the trailing space in `prefix`, and give the actor substrate's egress
trust bundle, since an `https` rule has the gateway terminate its TLS. The
gateway replaces a header only if the request carries it, so the actor must
send `Authorization` with a placeholder value:

```bash
curl -H 'Authorization: placeholder' https://storage.googleapis.com/storage/v1/b/BUCKET/o
```

Without the header the request goes out with no token. A request for a
profile the actor's atespace isn't granted gets a 403, and one made while the
provider or STS is down gets a retryable 503.

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
hack/release/draft-release.sh [--dry-run] <tag>   # draft the GitHub release for a pushed tag;
                                                  # needs jq and gh logged in with write access, even for --dry-run
```

Three packages are copies of substrate code kept in step by hand, since only
substrate's public `api/` and `pkg/` packages can be imported:
`internal/credbundle` of substrate's `internal/credbundle`, `internal/mtls` of
the server credentials in `cmd/credential-provider/kubernetes-secrets`, and
`internal/ateapiclient` of substrate's `internal/ateapiauth`.
