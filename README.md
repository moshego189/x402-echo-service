# x402 Echo Service

A minimal, honest [x402](https://x402.gitbook.io/x402) resource server, built for security
research into the x402 protocol and its discovery layer.

## What it does

`POST /echo` with `{"message": "..."}` returns the message, its SHA-256 digest, and a server
timestamp. It advertises a price of $0.001 USDC on Base and returns a spec-conformant
`402 Payment Required` with a `WWW-Authenticate` challenge.

**Payment is never settled.** Any payment authorization received is discarded unsettled and
unlogged, so callers are not charged. This is stated in the service's own `x-guidance`.

## Routes

| Route | Auth | Description |
| --- | --- | --- |
| `GET /` | free | Service metadata |
| `GET /openapi.json` | free | Discovery document (OpenAPI 3.1) |
| `POST /echo` | paid ($0.001) | Echo with SHA-256 digest |

## Discovery

Advertises `x-payment-info`, `info.x-guidance`, per-route input/output schemas, and
`extensions.bazaar.schema` in the 402 body. Passes `npx -y @agentcash/discovery@latest discover`
with no warnings.

The advertised origin is derived per-request from `x-forwarded-proto` / `x-forwarded-host`, so the
realm always matches the public hostname agents call. Override with `X402_PUBLIC_BASE` if needed.

## Run

```bash
node server.js            # PORT defaults to 4404
```

Config via env: `PORT`, `X402_PAYTO`, `X402_AMOUNT`, `X402_PUBLIC_BASE`.

No dependencies — Node standard library only.
