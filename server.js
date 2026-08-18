#!/usr/bin/env node
'use strict';
/*
 * Honest, AgentCash-discoverable x402 service. Deliberately SEPARATE from the
 * adversarial lab so that registering it cannot expose anyone to those scenarios.
 *
 * Ethical posture: we have no facilitator credentials, so we CANNOT settle. Rather
 * than retain third-party authorizations we can't settle, any payment payload is
 * served and then DISCARDED unsettled and unlogged. Nobody loses money and no
 * bearer instrument is kept. This is stated in the service guidance.
 */
const http = require('http');
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

const GUIDANCE =
 'Echo service for x402 protocol research. POST a JSON body with a "message" string; ' +
 'the response returns the message, its SHA-256 digest, and a server timestamp. ' +
 'Payment is advertised for protocol-conformance testing but is never settled: any ' +
 'payment authorization received is discarded unsettled and unlogged, so callers are ' +
 'not charged. Operated for security research into the x402 discovery layer.';

const INPUT_SCHEMA = { type:'object', required:['message'], additionalProperties:false,
  properties:{ message:{ type:'string', minLength:1, maxLength:4096, description:'Text to echo back.' } } };
const OUTPUT_SCHEMA = { type:'object', required:['echo','sha256','timestamp'],
  properties:{ echo:{type:'string'}, sha256:{type:'string'}, timestamp:{type:'string',format:'date-time'} } };

function paymentOption(PUBLIC) { return {
  scheme:'exact', network:NET, asset:ASSET, payTo:PAYTO, amount:AMOUNT,
  currency:ASSET, resource:`${PUBLIC}${ROUTE}`, description:GUIDANCE,
  mimeType:'application/json', maxTimeoutSeconds:300,
  extra:{ name:'USD Coin', version:'2' },
}; }

function paymentRequiredBody(PUBLIC) {
  return { x402Version:2, error:'Payment required: $0.001 USDC', reason_code:'payment_required',
    resource:{ url:`${PUBLIC}${ROUTE}`, description:GUIDANCE, mimeType:'application/json', serviceName:'x402 research echo' },
    accepts:[paymentOption(PUBLIC)],
    extensions:{ bazaar:{
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
  if (p==='/favicon.ico'){ res.writeHead(200,{'content-type':'image/x-icon'}); return res.end(FAVICON); }
  if (p==='/') return J(200,{ service:'x402 research echo', paid_route:`POST ${ROUTE}`,
      openapi:`${PUBLIC}/openapi.json`, guidance:GUIDANCE });

  if (p===ROUTE){
    const hdr = req.headers['payment-signature'] || req.headers['x-payment'];
    let raw=''; req.on('data',c=>{ raw+=c; if(raw.length>1e6) req.destroy(); });
    return req.on('end',()=>{
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
          `description="x402 research echo ($0.001 USDC)"`,
        ].join(' ');
        return J(402,b,{ 'x-402-version':'2',
          'www-authenticate':challenge,
          'payment-required':Buffer.from(JSON.stringify(b)).toString('base64') });
      }
      // Authorization received: serve, then DISCARD unsettled and unlogged.
      let msg=''; try{ msg=String(JSON.parse(raw||'{}').message ?? ''); }catch(e){}
      if(!msg) return J(400,{ error:'body must be {"message": "<string>"}' });
      return J(200,{ echo:msg, sha256:crypto.createHash('sha256').update(msg).digest('hex'),
        timestamp:new Date().toISOString(),
        note:'payment authorization received and discarded unsettled; you were not charged' });
    });
  }
  return J(404,{ error:'not found', routes:['/', ROUTE, '/openapi.json'] });
}).listen(PORT, ()=>{
  console.log(`x402 echo service listening on :${PORT}`);
  console.log(`  origin: ${FIXED_PUBLIC || 'derived from request headers'}`);
  console.log(`  routes: GET / , GET /openapi.json , POST ${ROUTE}`);
});
