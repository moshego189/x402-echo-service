#!/usr/bin/env node
'use strict';
/*
 * x402 research echo - Coinbase SDK build.
 *
 * Same service, same payTo, same advertised metadata as the stdlib build in
 * ../deploy, but payment handling comes from the official packages:
 *   @x402/express          - middleware
 *   @x402/core/server      - x402ResourceServer
 *   @x402/evm/exact/server - the `exact` scheme
 *   @coinbase/cdp-sdk/x402 - createCdpFacilitatorClient
 *
 * Per Coinbase's own guidance for a server that already speaks x402, this uses
 * createCdpFacilitatorClient() with an explicit payTo rather than
 * createX402Server(), which provisions its own receiver wallet and would move
 * payments off the address this service is already indexed under.
 *
 * Ordering: the middleware verifies, the handler delivers, settlement follows.
 * A charge therefore cannot precede delivery. The receipt lands in the
 * PAYMENT-RESPONSE header, not the response body.
 *
 * The advertised description MUST stay under 500 characters: the facilitator
 * rejects any payment payload containing a longer string, and conformant
 * clients echo this field into the payload they sign.
 */
import express from 'express';
import crypto from 'node:crypto';
import { paymentMiddleware } from '@x402/express';
import { x402ResourceServer } from '@x402/core/server';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { createCdpFacilitatorClient } from '@coinbase/cdp-sdk/x402';

const PORT   = +(process.env.PORT || 4404);
const PAYTO  = process.env.X402_PAYTO || '0x9Cc774A8eD49d89cBA1A288F4a050B8F7FbA77EE';
const NET    = 'eip155:8453';
const ROUTE  = '/echo';
const PRICE  = '$0.001';
const ASSET  = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const AMOUNT = '1000';

const SERVICE_NAME = 'x402 research echo';
const CATEGORY = 'Infra';
const SUMMARY = 'Paid echo endpoint for x402 conformance testing. POST a message, '
  + 'get it back with its SHA-256 digest, a server timestamp, and the settlement '
  + 'transaction hash. $0.001 USDC on Base per call.';
// Only the first five tags survive the indexer's cap, so order matters.
const TAGS = ['x402', 'echo', 'protocol-conformance', 'security-research', 'agents',
  'pay-per-call', 'micro-usdc', 'sha256', 'developer-tools', 'base'];

const DESC_CAP = 500;
function capped(t) {
  if (t.length <= DESC_CAP) return t;
  console.warn(`[config] description is ${t.length} chars, over the ${DESC_CAP} cap - truncating`);
  return t.slice(0, DESC_CAP - 1) + '…';
}
// Accuracy note: this build delivers the response and THEN settles, so the
// handler cannot know the transaction hash and the body does not carry one.
// The receipt is in the PAYMENT-RESPONSE header. Do not reinstate a claim that
// the hash is in the body.
const GUIDANCE = capped(
  'Echo service for x402 protocol research. POST a JSON body with a "message" string; '
  + 'the response returns the message, its SHA-256 digest and a server timestamp. '
  + 'Payment is live: $0.001 USDC on Base. The authorization is verified, the response is '
  + 'delivered, and settlement is requested afterwards via the Coinbase CDP facilitator, so '
  + 'callers ARE charged and no charge can precede delivery. The settlement receipt is '
  + 'returned in the PAYMENT-RESPONSE header.');

const INPUT_SCHEMA = { type: 'object', required: ['message'], additionalProperties: false,
  properties: { message: { type: 'string', minLength: 1, maxLength: 4096,
    description: 'Text to echo back.' } } };
const OUTPUT_SCHEMA = { type: 'object', required: ['echo', 'sha256', 'timestamp'],
  properties: { echo: { type: 'string' }, sha256: { type: 'string' },
    timestamp: { type: 'string', format: 'date-time' } } };

const ICON = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAIAAADTED8xAAACUUlEQVR42u3TMQ0AIAwAwUpgRgD+ZTEwIKEbM2MJl5yCTz5aH/CtkAADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAABhABQwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABoDyA8y14TAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABgADgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwwKsDQAUGwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAABlABA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4AB4FoCea769kb5NpoAAAAASUVORK5CYII=', 'base64');

// Origin is derived per-request from proxy headers so the advertised realm always
// matches the public host agents actually call.
const FIXED_PUBLIC = (process.env.X402_PUBLIC_BASE || '').replace(/\/+$/, '');
function originOf(req) {
  if (FIXED_PUBLIC) return FIXED_PUBLIC;
  const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim()
    || (req.socket && req.socket.encrypted ? 'https' : 'http');
  const host = (req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`)
    .split(',')[0].trim();
  return `${proto}://${host}`;
}
// The middleware needs a stable origin at config time; requests still report theirs.
const PUBLIC = FIXED_PUBLIC || `http://localhost:${PORT}`;

// Same bazaar declaration the stdlib build ships, including the fields the
// Bazaar ranks on: serviceName, category, summary, tags, coverImage.
const BAZAAR = {
  serviceName: SERVICE_NAME,
  category: CATEGORY,
  summary: SUMMARY,
  tags: TAGS,
  coverImage: `${PUBLIC}/icon.png`,
  info: {
    input: { type: 'http', method: 'POST', bodyType: 'json', body: { message: 'hello world' } },
    output: { type: 'json', example: { echo: 'hello world',
      sha256: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
      timestamp: '2026-08-18T12:00:00.000Z' } },
  },
  schema: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object', required: ['input', 'output'],
    properties: {
      input: { type: 'object', required: ['type', 'bodyType', 'body'],
        properties: { type: { const: 'http' }, method: { enum: ['POST'] },
          bodyType: { enum: ['json'] }, body: INPUT_SCHEMA } },
      output: { type: 'object', required: ['type', 'example'],
        properties: { type: { const: 'json' }, example: OUTPUT_SCHEMA } },
    },
  },
};

const OPENAPI = pub => ({
  openapi: '3.1.0',
  info: { title: 'x402 Research Echo', version: '1.0.0',
    description: GUIDANCE, 'x-guidance': GUIDANCE },
  servers: [{ url: pub }],
  'x-payment-info': { price: { mode: 'fixed', currency: 'USD', amount: '0.001' },
    protocols: [{ x402: { network: NET, scheme: 'exact', asset: ASSET, payTo: PAYTO, amount: AMOUNT } }] },
  'x-agentcash-agent-auth': { mode: 'none' },
  paths: {
    '/': { get: { operationId: 'index', summary: 'Service metadata', security: [],
      responses: { 200: { description: 'Service metadata',
        content: { 'application/json': { schema: { type: 'object' } } } } } } },
    '/openapi.json': { get: { operationId: 'openapi', summary: 'This OpenAPI document', security: [],
      responses: { 200: { description: 'OpenAPI document',
        content: { 'application/json': { schema: { type: 'object' } } } } } } },
    [ROUTE]: { post: { operationId: 'echo', summary: 'Echo a message with its SHA-256 digest',
      description: GUIDANCE, 'x-guidance': GUIDANCE,
      'x-payment-info': { price: { mode: 'fixed', currency: 'USD', amount: '0.001' },
        protocols: [{ x402: { network: NET, scheme: 'exact', asset: ASSET, payTo: PAYTO, amount: AMOUNT } }] },
      requestBody: { required: true, content: { 'application/json':
        { schema: INPUT_SCHEMA, example: { message: 'hello world' } } } },
      responses: {
        200: { description: 'Echo result', content: { 'application/json': { schema: OUTPUT_SCHEMA } } },
        402: { description: 'Payment Required (x402)',
          content: { 'application/json': { schema: { type: 'object' } } } },
      } } },
  },
});

function badInput(b) {
  if (b === null || typeof b !== 'object' || Array.isArray(b)) return 'body must be a JSON object';
  const extra = Object.keys(b).filter(k => k !== 'message');
  if (extra.length) return `unexpected propert${extra.length > 1 ? 'ies' : 'y'}: ${extra.join(', ')}`;
  if (typeof b.message !== 'string') return 'message must be a string';
  if (b.message.length < 1 || b.message.length > 4096) return 'message must be 1-4096 characters';
  return null;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);

// Free routes are registered BEFORE the payment middleware, so they stay free.
app.get('/', (req, res) => res.json({ service: SERVICE_NAME, paid_route: `POST ${ROUTE}`,
  openapi: `${originOf(req)}/openapi.json`, guidance: GUIDANCE }));
app.get(['/openapi.json', '/.well-known/openapi.json'], (req, res) => res.json(OPENAPI(originOf(req))));
app.get('/icon.png', (_req, res) => {
  res.set('content-type', 'image/png').set('cache-control', 'public, max-age=86400').send(ICON);
});
app.get('/favicon.ico', (_req, res) => {
  res.set('content-type', 'image/png').send(ICON);
});

// The SDK's default 402 body is `{}` and it sends no WWW-Authenticate. Both matter:
// discovery tooling and the indexer read the JSON body, and the stdlib build this
// replaces advertised both. Mirror the PAYMENT-REQUIRED header into the body so the
// two can never disagree, and re-add the challenge header.
app.use((req, res, next) => {
  const origJson = res.json.bind(res);
  res.json = body => {
    if (res.statusCode === 402) {
      const hdr = res.getHeader('PAYMENT-REQUIRED') || res.getHeader('payment-required');
      if (hdr) {
        try {
          const decoded = JSON.parse(Buffer.from(String(hdr), 'base64').toString('utf8'));
          const opt = (decoded.accepts || [])[0] || {};
          res.setHeader('x-402-version', '2');
          res.setHeader('access-control-expose-headers',
            'payment-response, payment-required, x-402-version');
          res.setHeader('www-authenticate', [
            'Payment',
            `realm="${PUBLIC}"`,
            'protocol="x402"',
            `scheme="${opt.scheme || 'exact'}"`,
            `network="${opt.network || NET}"`,
            `currency="${opt.asset || ASSET}"`,
            `amount="${opt.amount || AMOUNT}"`,
            `payTo="${opt.payTo || PAYTO}"`,
            `resource="${PUBLIC}${ROUTE}"`,
            `description="x402 research echo - $0.001 USDC (caller is charged)"`,
          ].join(' '));
          return origJson(decoded);
        } catch (e) { /* fall through to the original body */ }
      }
    }
    return origJson(body);
  };
  next();
});

// Reject wrong methods on the paid path before the middleware sees them, so the
// 402 challenge and the OpenAPI document cannot disagree about the verb.
app.all(ROUTE, (req, res, next) => {
  if (req.method !== 'POST') return res.status(405).set('allow', 'POST')
    .json({ error: 'method not allowed', allow: 'POST' });
  next();
});

const facilitator = createCdpFacilitatorClient();       // reads CDP_API_KEY_ID / _SECRET
const server = new x402ResourceServer(facilitator);
server.register(NET, new ExactEvmScheme());

app.use(paymentMiddleware({
  [`POST ${ROUTE}`]: {
    accepts: { scheme: 'exact', price: PRICE, network: NET, payTo: PAYTO },
    resource: `${PUBLIC}${ROUTE}`,
    description: GUIDANCE,
    mimeType: 'application/json',
    serviceName: SERVICE_NAME,
    tags: TAGS,
    iconUrl: `${PUBLIC}/icon.png`,
    extensions: { bazaar: BAZAAR },
  },
}, server));

// Body parsing happens here, after payment: a malformed body must never
// preempt the 402 challenge. A parse failure is surfaced as our own 400.
app.post(ROUTE, express.json({ limit: '1mb' }), (err, req, res, next) => {
  if (err) return res.status(400).json({ error: 'body must be valid JSON' });
  return next();
});

// Reached only once payment has been verified by the middleware.
app.post(ROUTE, (req, res) => {
  const bad = badInput(req.body);
  if (bad) return res.status(400).json({ error: bad });
  const msg = req.body.message;
  res.json({ echo: msg,
    sha256: crypto.createHash('sha256').update(msg).digest('hex'),
    timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`x402 echo service (SDK build) listening on :${PORT}`);
  console.log(`  origin: ${FIXED_PUBLIC || 'derived from request headers'}`);
  console.log(`  payTo : ${PAYTO}`);
  console.log(`  creds : ${process.env.CDP_API_KEY_ID ? 'CDP key present' : 'NO CDP KEY - payments will fail'}`);
});
