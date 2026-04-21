# Cyphera Open KMIP Server

> **Alpha software. Development and test use only.** This release is not audited and is not suitable for production key custody. Secret material is currently stored unwrapped in SQLite. Do not expose this service to untrusted networks unless you provide your own certs, CA, and API key.

Open-source KMIP 1.4 key management server for developers. Create keys, manage lifecycle, run server-side crypto, and connect KMIP clients — without fighting enterprise KMS platforms.

Works standalone or paired with [Cyphera Open PKI Server](https://github.com/cyphera-labs/open-pki-server) for mTLS certificate lifecycle.

## What it does

- KMIP 1.4 protocol over mTLS — implements core and extended operation handlers
- REST API for key management, crypto operations, and audit
- Server-side AES-GCM encrypt/decrypt, RSA/ECDSA sign/verify, HMAC, key wrapping
- Key lifecycle: create, activate, revoke, destroy, rekey, archive, recover
- RSA and ECDSA key pair generation
- X.509 certificate storage
- Custom per-key attributes
- Audit logging with client identity tracking
- SQLite storage with WAL mode and secure delete
- Dev mode: `--dev` generates mTLS certs and API key instantly
- Single binary. No external dependencies.

## Install

```bash
go install github.com/cyphera-labs/open-kmip-server/cmd/open-kmip@latest
```

Or use Docker:

```bash
docker run -d -p 5696:5696 -p 8200:8200 ghcr.io/cyphera-labs/open-kmip-server
```

## Quick Start

```bash
# Start in dev mode (auto-generates certs + API key)
open-kmip --dev
```

Prints client cert paths and API key to stdout. KMIP on `:5696`, REST API on `:8200`.

```bash
# Create a key
curl -sk -H "Authorization: Bearer $API_KEY" \
  -X POST https://localhost:8200/v1/keys \
  -d '{"name":"my-aes-key","algorithm":"AES","length":256}'

# Activate it
curl -sk -H "Authorization: Bearer $API_KEY" \
  -X POST https://localhost:8200/v1/keys/$UID/activate

# Encrypt something
curl -sk -H "Authorization: Bearer $API_KEY" \
  -X POST https://localhost:8200/v1/keys/$UID/encrypt \
  -d '{"data":"aGVsbG8gd29ybGQ="}'
```

## With Open PKI Server

Generate mTLS certs using [Open PKI Server](https://github.com/cyphera-labs/open-pki-server):

```bash
open-pki init-ca --name kmip-root --out ./certs

open-pki issue-server-cert \
  --profile kmip-server \
  --cn localhost --san localhost --san 127.0.0.1 \
  --out ./certs

open-pki issue-client-cert \
  --profile kmip-client \
  --cn my-app \
  --out ./certs

open-kmip \
  --cert ./certs/localhost.pem \
  --key ./certs/localhost-key.pem \
  --ca ./certs/ca.pem \
  --api-key my-secret
```

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/keys` | Create key or key pair |
| `GET` | `/v1/keys` | List keys |
| `GET` | `/v1/keys/{uid}` | Get key metadata |
| `POST` | `/v1/keys/{uid}/activate` | Activate |
| `POST` | `/v1/keys/{uid}/revoke` | Revoke |
| `DELETE` | `/v1/keys/{uid}` | Destroy |
| `POST` | `/v1/keys/{uid}/rekey` | Rekey |
| `POST` | `/v1/keys/{uid}/encrypt` | Encrypt (AES-GCM) |
| `POST` | `/v1/keys/{uid}/decrypt` | Decrypt |
| `POST` | `/v1/keys/{uid}/sign` | Sign (RSA/ECDSA) |
| `POST` | `/v1/keys/{uid}/verify` | Verify signature |
| `POST` | `/v1/keys/{uid}/mac` | HMAC-SHA256 |
| `POST` | `/v1/keys/{uid}/wrap` | Wrap key |
| `POST` | `/v1/keys/{uid}/unwrap` | Unwrap key |
| `POST` | `/v1/certificates` | Upload certificate |
| `GET` | `/v1/connections` | Active KMIP connections |
| `GET` | `/v1/status` | Server status |
| `GET` | `/v1/audit` | Audit log |

## KMIP Protocol

Implements a growing subset of KMIP 1.4 over TTLV binary encoding. Third-party interoperability is preliminary — only operations covered by the test suite should be treated as compatibility targets for this alpha.

Create, CreateKeyPair, Register, ReKey, DeriveKey, Locate, Check, Get, GetAttributes, GetAttributeList, AddAttribute, ModifyAttribute, DeleteAttribute, ObtainLease, Activate, Revoke, Destroy, Archive, Recover, Query, Poll, DiscoverVersions, Encrypt, Decrypt, Sign, SignatureVerify, MAC

### Compatible Clients

- [Cyphera KMIP clients](https://github.com/cyphera-labs) — Go, Java, Python, Node.js, Rust, .NET, PHP, Ruby, Swift
- PyKMIP
- Other KMIP 1.4 clients (compatibility testing ongoing)

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--dev` | | `false` | Dev mode with auto-generated certs |
| `--host` | | `0.0.0.0` | Listen address |
| `--port` | | `5696` | KMIP protocol port |
| `--api-port` | | `8200` | REST API port (0 to disable) |
| `--api-key` | `KMIP_API_KEY` | | REST API key |
| `--cert` | | | Server certificate PEM |
| `--key` | | | Server private key PEM |
| `--ca` | | | CA certificate PEM |
| `--storage` | | `sqlite` | `sqlite` or `memory` |
| `--db` | | `open-kmip.db` | SQLite database path |

## License

Apache License 2.0

## Links

- [Cyphera Labs](https://github.com/cyphera-labs) — open-source cryptography infrastructure
- [Open PKI Server](https://github.com/cyphera-labs/open-pki-server) — certificate lifecycle
- [KMIP Clients](https://github.com/cyphera-labs) — Go, Java, Python, Node.js, Rust, .NET, PHP, Ruby, Swift
