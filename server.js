#!/usr/bin/env node
'use strict';
/*
 * Honest, AgentCash-discoverable x402 service. Deliberately SEPARATE from the
 * adversarial lab so that registering it cannot expose anyone to those scenarios.
 *
 * Payment posture, controlled by X402_SETTLE:
 *   X402_SETTLE=1  -> verify, then settle via the CDP facilitator. Callers ARE charged.
 *   unset / 0      -> verify, then discard the authorization. Callers are not charged.
 * Either way the advertised guidance text is generated from the same flag, so the
 * description can never disagree with the behaviour.
 *
 * Ordering guarantee: the response body is computed BEFORE settlement is requested,
 * so settlement can never succeed for a response we were unable to produce. If the
 * settle call's outcome is unknown (transport failure), we say so and return the
 * authorization nonce rather than falsely claiming the caller was not charged.
 * No authorization is retained after the request completes.
 */
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const PORT   = +(process.env.PORT || 4404);
// Origin is derived per-request from proxy headers so the advertised realm always
// matches the public host agents actually call (works on Render/Vercel/Fly/etc).
const FIXED_PUBLIC = (process.env.X402_PUBLIC_BASE || '').replace(/\/+$/,'');
function originOf(req){
  if (FIXED_PUBLIC) return FIXED_PUBLIC;
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host  = (req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`).split(',')[0].trim();
  return `${proto}://${host}`;
}
const PAYTO  = process.env.X402_PAYTO || '0x9Cc774A8eD49d89cBA1A288F4a050B8F7FbA77EE';
const ASSET  = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const AMOUNT = process.env.X402_AMOUNT || '1000';   // $0.001
const NET    = 'eip155:8453';
const ROUTE  = '/echo';

const SETTLE = process.env.X402_SETTLE === '1';

const GUIDANCE = SETTLE ?
 ('Echo service for x402 protocol research. POST a JSON body with a "message" string; ' +
  'the response returns the message, its SHA-256 digest, and a server timestamp. ' +
  'Payment is live: $0.001 USDC on Base is verified and then settled through the Coinbase ' +
  'CDP facilitator, so callers ARE charged. The response body is computed before ' +
  'settlement is requested, and the settlement transaction hash is returned both in the ' +
  'response body and in the PAYMENT-RESPONSE header. Operated for security research into ' +
  'the x402 discovery layer.')
 :
 ('Echo service for x402 protocol research. POST a JSON body with a "message" string; ' +
  'the response returns the message, its SHA-256 digest, and a server timestamp. ' +
  'Payment is advertised and cryptographically verified but never settled: the ' +
  'authorization is discarded after verification, so callers are not charged. ' +
  'Operated for security research into the x402 discovery layer.');

// ---------------------------------------------------------------------------
// CDP facilitator client. Stdlib only - no npm dependency, so the Dockerfile
// (which never runs `npm install`) keeps working.
// Auth is an EdDSA/Ed25519 JWT per CDP's scheme; credentials come from the
// environment and are never logged.
// ---------------------------------------------------------------------------
const FACIL_HOST = 'api.cdp.coinbase.com';
const FACIL_BASE = '/platform/v2/x402';
const CDP_ID     = process.env.CDP_API_KEY_ID     || '';
const CDP_SECRET = process.env.CDP_API_KEY_SECRET || '';

function b64u(b){ return Buffer.from(b).toString('base64')
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

function cdpKey(){
  const raw = Buffer.from(CDP_SECRET, 'base64');
  return crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), raw.subarray(0,32)]),
    format:'der', type:'pkcs8' });
}

function cdpJwt(method, path){
  const now = Math.floor(Date.now()/1000);
  const hdr = { alg:'EdDSA', kid:CDP_ID, typ:'JWT', nonce:crypto.randomBytes(16).toString('hex') };
  const pl  = { sub:CDP_ID, iss:'cdp', aud:['cdp_service'], nbf:now, exp:now+120,
                uris:[`${method} ${FACIL_HOST}${path}`] };
  const si  = `${b64u(JSON.stringify(hdr))}.${b64u(JSON.stringify(pl))}`;
  return `${si}.${b64u(crypto.sign(null, Buffer.from(si), cdpKey()))}`;
}

// Resolves to the parsed facilitator response. Rejects on transport failure or
// non-2xx. `op` is 'verify' or 'settle'.
function facilitator(op, paymentPayload, paymentRequirements){
  const path = `${FACIL_BASE}/${op}`;
  const body = JSON.stringify({
    x402Version: paymentPayload.x402Version ?? 2,
    paymentPayload, paymentRequirements });
  return new Promise((resolve,reject)=>{
    const r = https.request({ host:FACIL_HOST, path, method:'POST', timeout:20000,
      headers:{ 'content-type':'application/json',
                'content-length':Buffer.byteLength(body),
                authorization:`Bearer ${cdpJwt('POST', path)}` } },
      resp=>{
        let d=''; resp.on('data',c=>d+=c);
        resp.on('end',()=>{
          let j=null; try{ j=JSON.parse(d); }catch(e){}
          if(resp.statusCode>=200 && resp.statusCode<300 && j) return resolve({ ...j,
            _ext: resp.headers['extension-responses'] || null });
          const e=new Error(`facilitator ${op} ${resp.statusCode}`);
          e.status=resp.statusCode; e.body=j; return reject(e);
        });
      });
    r.on('timeout',()=>{ r.destroy(new Error(`facilitator ${op} timeout`)); });
    r.on('error',reject);
    r.end(body);
  });
}

// Idempotency by EIP-3009 nonce. Nonces are single-use, which makes this a
// sound key. Bounds: 10k entries, FIFO eviction, 24h TTL. In-memory only - the
// free plan spins down, so we never promise durable recovery.
const RECEIPTS = new Map();
const RECEIPT_TTL = 24*3600*1000, RECEIPT_MAX = 10000;
function receiptGet(nonce){
  const r = RECEIPTS.get(nonce);
  if(!r) return null;
  if(Date.now()-r.at > RECEIPT_TTL){ RECEIPTS.delete(nonce); return null; }
  return r;
}
function receiptPut(nonce, rec){
  if(!nonce) return;
  if(RECEIPTS.size >= RECEIPT_MAX) RECEIPTS.delete(RECEIPTS.keys().next().value);
  RECEIPTS.set(nonce, { ...rec, at:Date.now() });
}

// The facilitator reports bazaar indexing here, on verify as well as settle.
// It is the only signal we get, so it is always logged.
function logExt(op, ext){
  if(!ext){ console.log(`[${op}] no EXTENSION-RESPONSES header`); return; }
  try { console.log(`[${op}] EXTENSION-RESPONSES`,
    JSON.stringify(JSON.parse(Buffer.from(ext,'base64').toString('utf8')))); }
  catch(e){ console.log(`[${op}] EXTENSION-RESPONSES (undecodable)`); }
}

// Enforce the declared input schema instead of only advertising it.
function badInput(b){
  if (b===null || typeof b!=='object' || Array.isArray(b)) return 'body must be a JSON object';
  const extra = Object.keys(b).filter(k=>k!=='message');
  if (extra.length) return `unexpected propert${extra.length>1?'ies':'y'}: ${extra.join(', ')}`;
  if (typeof b.message!=='string') return 'message must be a string';
  if (b.message.length<1 || b.message.length>4096) return 'message must be 1-4096 characters';
  return null;
}

const SERVICE_NAME = 'x402 research echo';

// Discovery metadata. The Bazaar ranks on how completely a resource describes
// itself, not on transaction volume, so these are load-bearing - but every one
// of them is an accurate description of what the route actually does.
const CATEGORY = 'Infra';
const SUMMARY  = 'Paid echo endpoint for x402 conformance testing. POST a message, '
  + 'get it back with its SHA-256 digest, a server timestamp, and the settlement '
  + 'transaction hash. $0.001 USDC on Base per call.';
const TAGS = ['x402','echo','agents','pay-per-call','micro-usdc',
  'protocol-conformance','security-research','sha256','developer-tools','base'];

// 256x256 PNG, served from /icon.png on this same origin.
const ICON = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAIAAADTED8xAAACUUlEQVR42u3TMQ0AIAwAwUpgRgD+ZTEwIKEbM2MJl5yCTz5aH/CtkAADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAABhABQwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABgADgAHAAGAAMAAYAAwABoDyA8y14TAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABjAABgADgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwgAEwwKsDQAUGwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAABlABA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4ABwABgADAAGAAMAAYAA4AB4FoCea769kb5NpoAAAAASUVORK5CYII=','base64');

const INPUT_SCHEMA = { type:'object', required:['message'], additionalProperties:false,
  properties:{ message:{ type:'string', minLength:1, maxLength:4096, description:'Text to echo back.' } } };
const OUTPUT_SCHEMA = { type:'object', required:['echo','sha256','timestamp'],
  properties:{ echo:{type:'string'}, sha256:{type:'string'}, timestamp:{type:'string',format:'date-time'},
    settlement:{ type:'object', description:'Present when a payment was settled.',
      properties:{ transaction:{type:'string'}, network:{type:'string'},
        amount:{type:'string'}, payer:{type:'string'} } } } };

function paymentOption(PUBLIC) { return {
  scheme:'exact', network:NET, asset:ASSET, payTo:PAYTO, amount:AMOUNT,
  currency:ASSET, resource:`${PUBLIC}${ROUTE}`, description:GUIDANCE,
  mimeType:'application/json', maxTimeoutSeconds:300,
  extra:{ name:'USD Coin', version:'2' },
}; }

function paymentRequiredBody(PUBLIC) {
  return { x402Version:2, error:'Payment required: $0.001 USDC', reason_code:'payment_required',
    resource:{ url:`${PUBLIC}${ROUTE}`, description:GUIDANCE, mimeType:'application/json',
      serviceName:SERVICE_NAME, tags:TAGS, iconUrl:`${PUBLIC}/icon.png` },
    accepts:[paymentOption(PUBLIC)],
    extensions:{ bazaar:{
      serviceName:SERVICE_NAME, category:CATEGORY, summary:SUMMARY, tags:TAGS,
      coverImage:`${PUBLIC}/icon.png`,
      info:{ input:{ type:'http', method:'POST', bodyType:'json', body:{ message:'hello world' } },
             output:{ type:'json', example:{ echo:'hello world',
               sha256:'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
               timestamp:'2026-08-18T12:00:00.000Z' } } },
      schema:{ $schema:'https://json-schema.org/draft/2020-12/schema', type:'object',
        required:['input','output'],
        properties:{
          input:{ type:'object', required:['type','bodyType','body'],
            properties:{ type:{const:'http'}, method:{enum:['POST']}, bodyType:{enum:['json']}, body:INPUT_SCHEMA } },
          output:{ type:'object', required:['type','example'],
            properties:{ type:{const:'json'}, example:OUTPUT_SCHEMA } } } },
    } } };
}

const OPENAPI = (PUBLIC) => ({
  openapi:'3.1.0',
  info:{ title:'x402 Research Echo', version:'1.0.0',
    description:GUIDANCE, 'x-guidance':GUIDANCE },
  servers:[{ url:PUBLIC }],
  'x-payment-info':{
    price:{ mode:'fixed', currency:'USD', amount:'0.001' },
    protocols:[{ x402:{ network:NET, scheme:'exact', asset:ASSET, payTo:PAYTO, amount:AMOUNT } }] },
  'x-agentcash-agent-auth':{ mode:'none' },
  components:{ securitySchemes:{ siwx:{ type:'apiKey', in:'header', name:'SIGN-IN-WITH-X' } } },
  paths:{
    '/':{ get:{ operationId:'index', summary:'Service metadata', security:[],
      responses:{ '200':{ description:'Service metadata', content:{ 'application/json':{
        schema:{ type:'object', properties:{ service:{type:'string'}, paid_route:{type:'string'} } } } } } } } },
    '/openapi.json':{ get:{ operationId:'openapi', summary:'This OpenAPI document', security:[],
      responses:{ '200':{ description:'OpenAPI document', content:{ 'application/json':{
        schema:{ type:'object' } } } } } } },
    [ROUTE]:{ post:{
    operationId:'echo', summary:'Echo a message with its SHA-256 digest',
    description:GUIDANCE, 'x-guidance':GUIDANCE,
    'x-payment-info':{
      price:{ mode:'fixed', currency:'USD', amount:'0.001' },
      protocols:[{ x402:{ network:NET, scheme:'exact', asset:ASSET, payTo:PAYTO, amount:AMOUNT } }] },
    requestBody:{ required:true, content:{ 'application/json':{ schema:INPUT_SCHEMA,
      example:{ message:'hello world' } } } },
    responses:{
      '200':{ description:'Echo result', content:{ 'application/json':{ schema:OUTPUT_SCHEMA } } },
      '402':{ description:'Payment Required (x402)', content:{ 'application/json':{
        schema:{ type:'object', properties:{ x402Version:{type:'integer'}, error:{type:'string'},
          accepts:{type:'array', items:{type:'object'}} } } } } },
    } } } },
});

const FAVICON = Buffer.from(
 'AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAA' +
 'A'.repeat(1400), 'base64');

http.createServer((req,res)=>{
  const PUBLIC = originOf(req);
  const u = new URL(req.url, PUBLIC);
  const p = u.pathname.replace(/\/+$/,'') || '/';
  const J = (code,obj,extra={}) => { res.writeHead(code,{'content-type':'application/json',
    'access-control-expose-headers':'payment-response, payment-required, x-402-version', ...extra});
    res.end(JSON.stringify(obj,null,2)); };

  if (p==='/openapi.json' || p==='/.well-known/openapi.json') return J(200, OPENAPI(PUBLIC));
  if (p==='/icon.png'){ res.writeHead(200,{'content-type':'image/png',
    'cache-control':'public, max-age=86400'}); return res.end(ICON); }
  if (p==='/favicon.ico'){ res.writeHead(200,{'content-type':'image/x-icon'}); return res.end(FAVICON); }
  if (p==='/') return J(200,{ service:'x402 research echo', paid_route:`POST ${ROUTE}`,
      openapi:`${PUBLIC}/openapi.json`, guidance:GUIDANCE });

  if (p===ROUTE){
    if (req.method !== 'POST')
      return J(405,{ error:'method not allowed', allow:'POST' },{ allow:'POST' });

    const hdr = req.headers['payment-signature'] || req.headers['x-payment'];
    let raw=''; req.on('data',c=>{ raw+=c; if(raw.length>1e6) req.destroy(); });

    return req.on('end', async ()=>{
      // The 402 challenge must come FIRST and must not depend on the body.
      // Coinbase's discovery validator probes this route with a non-conforming
      // body to find the challenge; answering 400 there fails the returns_402
      // preflight check and the resource is never indexed.
      if(!hdr){
        const b=paymentRequiredBody(PUBLIC);
        const challenge = [
          'Payment',
          `realm="${PUBLIC}"`,
          'protocol="x402"',
          'scheme="exact"',
          `network="${NET}"`,
          `currency="${ASSET}"`,
          `amount="${AMOUNT}"`,
          `payTo="${PAYTO}"`,
          `resource="${PUBLIC}${ROUTE}"`,
          `description="x402 research echo - $0.001 USDC${SETTLE?' (caller is charged)':' (verified, not charged)'}"`,
        ].join(' ');
        return J(402,b,{ 'x-402-version':'2',
          'www-authenticate':challenge,
          'payment-required':Buffer.from(JSON.stringify(b)).toString('base64') });
      }

      // A payment header is present. Validate the body now - before any
      // facilitator call - so a malformed request is never a reason to have
      // charged someone.
      let body; try{ body = JSON.parse(raw||'{}'); }
      catch(e){ return J(400,{ error:'body must be valid JSON' }); }
      const bad = badInput(body);
      if (bad) return J(400,{ error:bad });
      const msg = body.message;

      // A present-but-unparseable header is not a payment. Previously any
      // non-empty value bought the paid response.
      let payload;
      try {
        payload = JSON.parse(Buffer.from(String(hdr),'base64').toString('utf8'));
        if(!payload || typeof payload!=='object' || Array.isArray(payload)) throw new Error('shape');
      } catch(e) {
        const b=paymentRequiredBody(PUBLIC);
        b.error='PAYMENT-SIGNATURE must be a base64-encoded x402 payment payload';
        return J(402,b,{ 'x-402-version':'2' });
      }

      const reqs = paymentOption(PUBLIC);
      const nonce = payload?.payload?.authorization?.nonce ?? null;
      const msgHash = crypto.createHash('sha256').update(msg).digest('hex');

      // Replay handling comes BEFORE verify, so an authorization already spent
      // is never sent to the facilitator a second time.
      const prior = receiptGet(nonce);
      if(prior){
        if(prior.status==='unknown')
          return J(409,{ error:'a previous request for this authorization had an unknown '+
            'settlement outcome; refusing to attempt a second settlement. Check the '+
            'transaction on-chain by nonce.', authorization_nonce:nonce });
        if(prior.status==='settled'){
          if(prior.msgHash!==msgHash)
            return J(402,{ error:'this authorization was already consumed for a different '+
              'request body', authorization_nonce:nonce });
          return J(200,{ ...prior.out, settlement:prior.settlement,
            note:'this authorization was already settled by an earlier request; returning the '+
                 'original result and receipt. You were not charged again.' });
        }
      }

      if(!CDP_ID || !CDP_SECRET)
        return J(503,{ error:'facilitator not configured; no payment was processed' });

      // 1. Verify. Free, moves no money.
      if(!payload.extensions || !payload.extensions.bazaar)
        console.warn('[verify] payload carries no extensions.bazaar - this will index nothing');
      let v;
      try { v = await facilitator('verify', payload, reqs); logExt('verify', v._ext); }
      catch(e){
        console.error('[verify] failed', e.status||'', JSON.stringify(e.body||e.message));
        // Skeleton only - no signature, no key material. Needed because the
        // facilitator's schema error does not say which field was wrong.
        try { console.error('[verify] payload skeleton', JSON.stringify({
          top: Object.keys(payload),
          x402Version: payload.x402Version, x402VersionType: typeof payload.x402Version,
          accepted: payload.accepted ? Object.keys(payload.accepted) : null,
          acceptedScheme: payload.accepted?.scheme, acceptedNetwork: payload.accepted?.network,
          payloadKeys: payload.payload ? Object.keys(payload.payload) : null,
          extensions: payload.extensions ? Object.keys(payload.extensions) : null,
          resourceKeys: payload.resource ? Object.keys(payload.resource) : null })); } catch(_){}
        return J(502,{ error:'could not verify payment; you were not charged' }); }
      if(!v.isValid){
        const b=paymentRequiredBody(PUBLIC);
        b.error=`payment authorization is not valid: ${v.invalidReason||'unspecified'}`;
        return J(402,b,{ 'x-402-version':'2' });
      }

      // 2. Compute the deliverable BEFORE requesting settlement, so settlement
      //    can never succeed for a response we were unable to produce.
      const out = { echo:msg, sha256:msgHash, timestamp:new Date().toISOString() };

      if(!SETTLE)
        return J(200,{ ...out,
          note:'payment verified and then discarded unsettled; you were not charged' });

      // 3. Settle.
      let st;
      try { st = await facilitator('settle', payload, reqs); logExt('settle', st._ext); }
      catch(e){
        console.error('[settle] failed', e.status||'', JSON.stringify(e.body||e.message));
        // The outcome is genuinely unknown: it may have settled before the
        // connection failed. Record that BEFORE returning, so a retry cannot
        // re-enter /settle on a nonce that may already have moved money.
        receiptPut(nonce,{ status:'unknown', msgHash });
        return J(502,{ error:'settlement outcome unknown - the facilitator did not respond. '+
          'If it settled, the payment is recoverable on-chain by authorization nonce.',
          authorization_nonce:nonce });
      }
      if(!st.success){
        // NEVER say "you were not charged" here. A replayed authorization fails
        // precisely because it already settled once - on that path the caller
        // WAS charged, by the earlier request.
        receiptPut(nonce,{ status:'failed', msgHash });
        return J(502,{ error:`settlement failed: ${st.errorReason||'unspecified'}; `+
          'this request made no charge', authorization_nonce:nonce });
      }

      const settlement = { transaction:st.transaction, network:st.network,
        amount:st.amount ?? AMOUNT, payer:st.payer ?? null,
        recovery:'receipt held in memory only; recovery window ends at process restart' };

      // Receipt is durable-as-we-can-make-it BEFORE delivery is attempted, so
      // there is no path where money moved and no receipt exists.
      receiptPut(nonce,{ status:'settled', msgHash, out, settlement });

      res.on('error',()=>console.error('DELIVERY_FAILED',
        JSON.stringify({ nonce, transaction:st.transaction, payer:st.payer ?? null })));
      res.on('close',()=>{ if(!res.writableFinished) console.error('DELIVERY_FAILED',
        JSON.stringify({ nonce, transaction:st.transaction, payer:st.payer ?? null })); });

      return J(200,{ ...out, settlement },
        { 'payment-response':Buffer.from(JSON.stringify({
            success:true, transaction:st.transaction, network:st.network,
            payer:st.payer ?? null })).toString('base64') });
    });
  }

  return J(404,{ error:'not found', routes:['/', ROUTE, '/openapi.json'] });
}).listen(PORT, ()=>{
  console.log(`x402 echo service listening on :${PORT}`);
  console.log(`  origin: ${FIXED_PUBLIC || 'derived from request headers'}`);
  console.log(`  routes: GET / , GET /openapi.json , POST ${ROUTE}`);
});
