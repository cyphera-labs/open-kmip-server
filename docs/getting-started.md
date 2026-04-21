# Getting Started

## Install

### Docker (recommended)

```bash
docker run -d -p 5696:5696 -p 8200:8200 ghcr.io/cyphera-labs/open-kmip-server
```

### From source

```bash
go install github.com/cyphera-labs/open-kmip-server/cmd/open-kmip@latest
```

## Dev Mode

Start with zero config:

```bash
open-kmip --dev
```

This auto-generates:
- Self-signed CA, server cert, and client cert in `~/.open-kmip/certs/`
- A random API key (printed to stdout)

The server starts with:
- KMIP protocol on port 5696 (mTLS)
- REST API on port 8200 (TLS)
- Dashboard at https://localhost:8200/

## Create Your First Key

### Via REST API

```bash
# Use the API key printed at startup
API_KEY="dev-..."

# Create an AES-256 key
curl -sk -H "Authorization: Bearer $API_KEY" \
  -X POST https://localhost:8200/v1/keys \
  -d '{"name":"my-key","algorithm":"AES","length":256}'

# Activate it
curl -sk -H "Authorization: Bearer $API_KEY" \
  -X POST https://localhost:8200/v1/keys/$UID/activate

# Encrypt data
curl -sk -H "Authorization: Bearer $API_KEY" \
  -X POST https://localhost:8200/v1/keys/$UID/encrypt \
  -d '{"data":"aGVsbG8gd29ybGQ="}'
```

### Via KMIP Client

```go
import kmip "github.com/cyphera-labs/kmip-go"

client, err := kmip.NewClient(kmip.ClientOptions{
    Host:       "localhost",
    ClientCert: "~/.open-kmip/certs/client.pem",
    ClientKey:  "~/.open-kmip/certs/client-key.pem",
    CACert:     "~/.open-kmip/certs/ca.pem",
})
defer client.Close()

// Create and fetch a key
result, _ := client.Create("my-key", kmip.AlgorithmAES, 256)
client.Activate(result.UniqueIdentifier)
key, _ := client.FetchKey("my-key")
```

## Production Mode

```bash
open-kmip \
  --cert /certs/server.pem \
  --key /certs/server-key.pem \
  --ca /certs/ca.pem \
  --api-key $KMIP_API_KEY \
  --db /data/open-kmip.db
```

Required flags:
- `--cert`, `--key`, `--ca` — TLS certificates (use [Open PKI Server](https://github.com/cyphera-labs/open-pki-server) to generate)
- `--api-key` or `KMIP_API_KEY` env var — REST API authentication

## Dashboard

Open https://localhost:8200/ in your browser.

- In dev mode: loads directly with a yellow DEV MODE banner
- In production mode: shows a login screen (enter the API key)

Pages:
- **Overview** — key stats, connections, uptime, recent audit
- **Keys** — list, create, activate, revoke with status filters
- **Connections** — active KMIP client connections
- **Audit** — full operation audit log
