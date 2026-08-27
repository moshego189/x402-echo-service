# x402 Echo Service

A minimal, honest [x402](https://x402.gitbook.io/x402) resource server, built for security
research into the x402 protocol and its discovery layer.

## What it does

`POST /echo` with `{"message": "..."}` returns the message, its SHA-256 digest, and a server
timestamp. It advertises a price of $0.001 USDC on Base and returns a spec-conformant
`402 Payment Required` with a `WWW-Authenticate` challenge.

**Payment behaviour is controlled by `X402_SETTLE`.**

- `X402_SETTLE=1` — the authorization is verified and then **settled** through the Coinbase CDP
  facilitator, so callers **are** charged $0.001 USDC. The response body is computed *before*
  settlement is requested, so settlement can never succeed for a response we could not produce.
  The settlement transaction hash is returned in the body and in `PAYMENT-RESPONSE`.
- unset / `0` — the authorization is verified and then discarded unsettled, so callers are not
  charged.

Whichever mode is active is stated in the service's own `x-guidance`, so the advertised
description always matches the actual behaviour. Requires `CDP_API_KEY_ID` and
`CDP_API_KEY_SECRET`; without them the paid route returns `503` rather than serving unpaid.

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

Config via env: `PORT`, `X402_PAYTO`, `X402_AMOUNT`, `X402_PUBLIC_BASE`, `X402_SETTLE`,
`CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`.

Built on the official packages: `@x402/express`, `@x402/core`, `@x402/evm` and
`@coinbase/cdp-sdk/x402` (`createCdpFacilitatorClient` with an explicit `payTo`, rather than
`createX402Server`, which provisions its own receiver wallet).

Four SDK defaults are deliberately overridden, because each one breaks discovery:

1. The middleware's 402 body defaults to `{}`, with the payment requirements only in the
   `PAYMENT-REQUIRED` header. Discovery tooling and the Bazaar indexer read the **body**, so
   the header is mirrored into it and the two cannot disagree.
2. No `WWW-Authenticate` is sent; it is re-added.
3. `resource.url` is derived per-request, which advertises the internal host when behind a
   proxy. The route pins `resource` explicitly.
4. `express.json()` answers a malformed body with 400 before the payment middleware can
   answer 402. Coinbase's discovery validator probes with exactly such a body, so a 400 there
   fails its `returns_402` check and the resource is never indexed. Body parsing therefore
   runs *after* payment.

`X402_SETTLE` is vestigial in this build: the SDK middleware always settles, and the
advertised guidance is written accordingly.
