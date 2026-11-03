# token-exchange credential provider

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A [substrate](https://github.com/agent-substrate/substrate) credential provider
that exchanges an actor's Substrate-minted JWT for an access token at an
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token endpoint, such as
Google Cloud STS. It implements substrate's `CredentialProvider` gRPC API
(`api/credprovider/v1`) for egress credential injection.
