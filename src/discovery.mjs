// Signed, bounded discovery. This does not manufacture institutional trust or registration.
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {profile,PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from './profile.mjs';
import {hash,canonical,hashBytes,demand,seal} from './canonical.mjs';
import {validateTrust,authorize} from './authority.mjs';
import {protocol,CONTRACT_HASH,SCHEMA_HASH,VERIFIER_HASH,CAPABILITY_ID,CAPABILITY_CLASS,RESOLUTION_ID,RESOLUTION_PATH} from './protocol.mjs';
import resultSchema from '../schemas/result.schema.json' with {type:'json'};
import resolutionSchema from '../schemas/discovery-resolution.schema.json' with {type:'json'};
import inputSchema from '../schemas/submission.schema.json' with {type:'json'};
import openapi from '../public/openapi.json' with {type:'json'};
import {validateWire} from './wire-schema.mjs';
import {STANDING_CAPABILITY} from './need.mjs';
import verifier from '../public/verifier-manifest.json' with {type:'json'};
import publicExample from '../public/examples/submission.TEST.json' with {type:'json'};
import {applicability,recursiveUse,exposurePaths} from './exposure.mjs';
import {agentCard} from './carrier.mjs';
export const SERVICE='WHP Standing';
export const PUBLISHER='Wheeler Hubbell Publishing';
export const CAPABILITY='Machine-verifiable standing under explicit authority and bounds.';
export const RECIPIENT='0x1050eddd8282623b0c263ed6bdbd42370bbc28d3';
export const NETWORK='eip155:8453';
export const USDC='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
export const profilePath='/v1/profiles/'+encodeURIComponent(PROFILE_ID)+'/'+PROFILE_VERSION;
export function livePaymentDestination(r){demand(r.payTo===RECIPIENT&&r.network===NETWORK&&r.asset===USDC&&r.extra.name==='USD Coin'&&r.extra.version==='2','LIVE_PAYMENT_DESTINATION_INVALID',503);}
export const currentOpenapi=service=>({...openapi,servers:[{url:service.origin}]});
export function resolution(service){
  const now=service.clock(),trust=validateTrust(service.trustBundle,service.rootPin,now),cert=trust.keys.get(service.keyId);
  demand(cert?.roles.includes('DISCOVERY'),'DISCOVERY_AUTHORITY_REQUIRED',503);
  const o=service.origin,ctx={scope:cert.scopes[0],jurisdiction:cert.jurisdictions[0]};
  const payload={version:'WHP-CAPABILITY-RESOLUTION-v1',capability_id:CAPABILITY_ID,capability_class:CAPABILITY_CLASS,resolution_id:RESOLUTION_ID,
    issuer:trust.profile.issuer,environment:trust.profile.environment,root_key_id:service.rootPin,
    observed_at:now,valid_until:Math.min(now+300,cert.valid_until,trust.profile.valid_until,trust.bundle.status_snapshot.payload.valid_until),
    trust_bundle:service.trustBundle,authority_context:ctx,service_origin:o,service_contract:{url:o+'/v1/contract',sha256:hash(contract(service))},openapi:{url:o+'/v1/openapi.json',sha256:hash(currentOpenapi(service))},
    artifacts:[{kind:'PROFILE',id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:o+'/v1/immutable/'+PROFILE_HASH,media_type:'application/json'},
      {kind:'CONTRACT',id:protocol().document.id,version:'1',sha256:CONTRACT_HASH,url:o+'/v1/immutable/'+CONTRACT_HASH,media_type:'application/json'},
      {kind:'SCHEMA',id:resultSchema.$id,version:'1',sha256:SCHEMA_HASH,url:o+'/v1/immutable/'+SCHEMA_HASH,media_type:'application/schema+json'},
      {kind:'VERIFIER',id:'urn:sha256:'+VERIFIER_HASH,version:'1',sha256:VERIFIER_HASH,url:o+verifier.path,media_type:'text/x-python'}],
    registry_template:o+'/v1/registry/{purchase_id}',provider_discovery:{interface:'capability-catalog-v1',url:service.catalogUrl??null},
    availability:trust.profile.environment==='TEST'?'TEST_ONLY':'CONFIGURED_LIVE_NOT_SALE_PROVEN'};
  const signed=seal('WHP-CAPABILITY-RESOLUTION-v1',payload,service.privateKey);
  authorize(signed,'WHP-CAPABILITY-RESOLUTION-v1','DISCOVERY',ctx,trust);validateWire(signed,resolutionSchema);return signed;
}
const input=k=>({'$input':k});
export function unadmittedProbe(){
  const bounds={scope:input('scope'),jurisdiction:input('jurisdiction'),valid_from:input('now_minus_1'),valid_until:input('now_plus_60')};
  return {kind:'UNADMITTED_SELF_ATTESTATION',purpose:'Inspect payment terms only. This probe cannot create source authority or positive standing.',wallet_signing:false,authority_established:false,
    source_protected:{type:'WHP-SOURCE-ATTESTATION-v1',algorithm:'Ed25519',canonicalization:'WHP-JCS-I1'},
    source_payload:{id:input('object_id'),version:input('object_version'),content:input('object_content'),locator:'urn:unadmitted:self-attestation',epistemic_status:'REPORT',
      qualifiers:['Unadmitted self-attestation for a boundary probe only.'],unknowns:[{id:'authority-unestablished',description:'No admitted source authority has been established for this probe.',blocks:['INFORM','RECOMMEND','EXECUTE']}],
      operations:[input('operation')],...bounds,status:'ACTIVE',prior_hash:null},
    submission_template:{version:'WHP-STANDING-SUBMISSION-v1.1',client_reference:input('client_reference'),authority:[],profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH},
      object:{id:input('object_id'),version:input('object_version'),root:input('node_hash')},bounds,requested_operation:input('operation'),nodes:[input('signed_node')],transitions:[]}};
}
export function verificationDocument(origin){return {
  service:SERVICE,version:'1.0.0',algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',
  source:{url:origin+verifier.path,sha256:verifier.sha256,language:'python',dependencies:{cryptography:'46.0.4',jsonschema:'4.26.0'}},
  invocation:{executable:'python3',arguments:['{mark}','--root-pin','{root_pin}','--registry','{registry}'],test_arguments:['--allow-test']},
  inputs:{mark:'Exact original UTF-8 bytes, not reserialized JSON.',root_pin:'Admitted SHA256 of root Ed25519 SPKI DER, not the payment address.',registry:'Fresh signed snapshot reached through the Mark-bound current capability resolution.'},
  outputs:{verified:'Cryptographic integrity, authority and independent evaluator replay.',current_standing:'ACTIVE, EXPIRED, LIMITED, WITHDRAWN, SUPERSEDED, or ASSESSED_NO_MARK.',live_completion_verified:'False: outside-buyer relationship is not established by a cryptographic verifier. technical_live_issuance_verified separately reports LIVE chain/status checks.'},
  safety:'Run downloaded verifier code only in a no-network, read-only, least-privilege sandbox. A valid signature is not an endorsement of arbitrary executable code.',
  independent_source:'https://github.com/wheelerhubbell/WHPStanding/tree/main/verify',
  settlement:'Use --rpc with an independently trusted HTTPS Base RPC to recheck finality and exact transfer. An RPC URL is not supplied by the Mark as an unquestionable oracle.'
};}
export function contract(service){const o=service.origin;return {
  version:'WHP-STANDING-CONTRACT-v1.1',service:SERVICE,capability:CAPABILITY,capability_id:CAPABILITY_ID,capability_class:CAPABILITY_CLASS,publisher:PUBLISHER,
  issuer:service.trustBundle.profile_authorization.payload.issuer,public_contract:protocol(),root_pin:service.rootPin,
  supported_properties:STANDING_CAPABILITY.requirements,
  supported_scopes:service.trustBundle.certificates.find(e=>hashBytes(Buffer.from(e.payload.public_key,'base64'))===service.keyId).payload.scopes,
  supported_jurisdictions:service.trustBundle.certificates.find(e=>hashBytes(Buffer.from(e.payload.public_key,'base64'))===service.keyId).payload.jurisdictions,
  environment:service.trustBundle.profile_authorization.payload.environment,
  profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:o+profilePath},
  purchase:{name:'WHP Standing Evaluation',method:'POST',url:o+'/v1/evaluations',content_type:'application/json',input_schema:o+'/schemas/submission.schema.json',input_schema_sha256:hash(inputSchema),result_schema:o+'/schemas/result.schema.json',
    requirements:service.requirements,charge_policy:'One evaluation, including a negative assessment. A failed assessment never receives a WHP Standing Mark. Retrieval and recovery never authorize a second payment.',
    prerequisites:'SOURCE and TRANSITION attestations must chain to admitted authorities with the exact scope, jurisdiction, time and operation. Paying does not supply missing authority.'},
  authentication:{purchase:'NONE_BEYOND_X402_PAYMENT',retrieval:'OPAQUE_PURCHASE_CAPABILITY',review:'Reviewer signatures apply only to review submissions.'},
  payment:{protocol:'x402-v2',required_header:'PAYMENT-REQUIRED',authorization_header:'PAYMENT-SIGNATURE',settlement_header:'PAYMENT-RESPONSE',required_extension:null,
    quote_pointer:'/extensions/whp-standing/info/quote',requirements_pointer:'/accepts/0',
    nonce:{source:'CLIENT_SELECTED_EIP3009_NONCE'},
    wallet_authority:'The buyer client must independently enforce its owner-approved network, token, recipient, per-purchase and aggregate limits before its own wallet signs. The service never possesses buyer wallet keys.',
    generic_client_compatibility:'Standard x402 v2 exact EIP-3009 clients, including client-selected random nonces. No WHP-specific client extension is required.',
    settlement:'No issuance before exact canonical finalized Base transfer and AuthorizationUsed event. An uncertain settle remains pending; recover using the same stored authorization.'},
  retrieval:{additional_charge:false,identity:'Root pin + cryptographically random 256-bit client_reference; exact submitted-object hash is immutable.',lost_response:'Use GET result or empty POST recovery with the opaque purchase capability. Do not generate a second wallet authorization.'},
  cold_probe:unadmittedProbe(),
  provider_discovery:{interface:'capability-catalog-v1',url:service.catalogUrl??null},
  verification_url:o+'/v1/verification',discovery_url:o+'/.well-known/whp-standing.json',mcp_url:o+'/mcp',
  establishes:profile().assessed,does_not_establish:profile().not_assessed,
  authority_admission:'HTTPS proves control of an origin, not institutional appointment. A buyer must admit the publisher root under its own trust policy; unknown authority remains unknown.',
  external_registrations:[],registration_claim:'No registration is claimed by serving this contract.'
};}
// Standard Bazaar declaration. Example is public TEST data, never a customer's object.
// Full input schema is a canonical public JSON Schema reference, not a permissive substitute.
// External catalog acceptance of remote $ref resolution remains separately evidenced.
export function bazaar(service){return {
  info:{input:{type:'http',method:'POST',bodyType:'json',body:publicExample,
    headers:{}},output:{type:'json'}},
  schema:{$schema:'https://json-schema.org/draft/2020-12/schema',type:'object',properties:{
    input:{type:'object',properties:{type:{type:'string',const:'http'},method:{type:'string',enum:['POST']},bodyType:{type:'string',enum:['json']},
      body:{$ref:service.origin+'/schemas/submission.schema.json',description:'TEST wire-shape example only. A LIVE evaluation requires currently admitted SOURCE and TRANSITION attestations. The complete purchase and authentication contract is '+service.origin+'/v1/contract'},
      headers:{type:'object',additionalProperties:{type:'string'}}},required:['type','method','bodyType','body'],additionalProperties:false},
    output:{type:'object',properties:{type:{type:'string',const:'json'}},required:['type'],additionalProperties:false}},required:['input']}
};}
const response=(body,type='application/json',method='GET',extra={})=>new Response(method==='HEAD'?null:typeof body==='string'?body:canonical(body)+'\n',{status:200,headers:{'content-type':type,'cache-control':'no-store','x-content-type-options':'nosniff',...extra}});
export async function discoveryRoute(service,req){const o=service.origin,u=new URL(req.url),p=u.pathname;if(!['GET','HEAD'].includes(req.method))return null;
  if(p==='/openapi.json')return response(currentOpenapi(service),'application/json',req.method);
  if(p==='/.well-known/agent-card.json'||p==='/.well-known/agent.json')return response(agentCard(o),'application/json',req.method);
  if(p==='/.well-known/x402')return response({version:1,resources:[o+'/v1/evaluations'],name:SERVICE,description:CAPABILITY,homepage:o,repository:'https://github.com/wheelerhubbell/WheelerHubbellPublishingStandingMark',machineReadable:{openapi:o+'/v1/openapi.json',contract:o+'/v1/contract',llmsTxt:o+'/llms.txt',applicability:o+'/discovery/applicability.json'},mcp:{remoteConnector:o+'/mcp'},payment:{protocol:'x402-v2',requirements:service.requirements,required_extension:null,generic_random_nonce_client_compatible:true,prerequisites_url:o+'/v1/contract'},registration_claim:'Self-published discovery only; external acceptance is separately evidenced.'},'application/json',req.method);
  if(p==='/discovery/applicability.json')return response(applicability(o),'application/json',req.method);
  if(p==='/discovery/recursive-use.json')return response(recursiveUse(o),'application/json',req.method);
  if(p==='/v1/profiles')return response({profiles:[{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH,url:o+profilePath}]},'application/json',req.method);
  if(p==='/discovery/capability.json')return response({version:'WHP-STANDING-CAPABILITY-v1',capability_id:CAPABILITY_ID,capability_class:CAPABILITY_CLASS,description:CAPABILITY,provider:{name:PUBLISHER,product:SERVICE},resolution_url:service.resolutionUrl,scope:'Declared provider capability, not a standing assessment or institutional admission.'},'application/json',req.method);
  if(p==='/discovery/provider-index.json')return response({interface:'capability-catalog-v1',providers:[{id:CAPABILITY_ID,capability_class:CAPABILITY_CLASS,properties:STANDING_CAPABILITY.requirements,scopes:contract(service).supported_scopes,jurisdictions:contract(service).supported_jurisdictions,resolution_url:service.resolutionUrl}],self_published:true,external_registration_established:false},'application/json',req.method);
  if(p===RESOLUTION_PATH)return response(resolution(service),'application/json',req.method);
  if(p==='/v1/contracts/mark-v1.json')return response(protocol().document,'application/json',req.method);
  if(p==='/schemas/discovery-resolution.schema.json')return response(resolutionSchema,'application/schema+json',req.method);
  const immutable=p.match(/^\/v1\/immutable\/([0-9a-f]{64})$/);
  if(immutable){const objects=new Map([[PROFILE_HASH,profile()],[CONTRACT_HASH,protocol().document],[SCHEMA_HASH,resultSchema]]);let value=objects.get(immutable[1]);if(!value){try{value=JSON.parse(await readFile(resolve(process.cwd(),'public/immutable',immutable[1]+'.json'),'utf8'));demand(hash(value)===immutable[1],'IMMUTABLE_HASH_MISMATCH',503);}catch(e){if(e.code!=='ENOENT')throw e;}}return value?response(value,'application/json',req.method,{'cache-control':'public, max-age=31536000, immutable'}):new Response(null,{status:404});}
  const link='<'+o+'/.well-known/api-catalog>; rel="api-catalog"';
  if(p==='/examples/submission.TEST.json')return response(publicExample,'application/json',req.method);
  if(p==='/v1/contract')return response(contract(service),'application/json',req.method);
  if(p==='/v1/verification')return response(verificationDocument(o),'application/json',req.method);
  if(p===profilePath)return response({profile:profile(),sha256:PROFILE_HASH,authorization:service.trustBundle.profile_authorization},'application/json',req.method);
  if(/^\/verification\/[0-9a-f]{64}\.py$/.test(p)){
    try{const bytes=await readFile(resolve(process.cwd(),'public',p.slice(1)));demand(hashBytes(bytes)===p.split('/').at(-1).slice(0,-3),'VERIFIER_ARTIFACT_HASH',503);return response(bytes.toString('utf8'),'text/plain; charset=utf-8',req.method,{'cache-control':'public, max-age=31536000, immutable'});}catch(e){if(e.code==='ENOENT')return new Response(null,{status:404});throw e;}}
  if(p==='/.well-known/api-catalog')return response({linkset:[{anchor:o+'/.well-known/api-catalog',item:[{href:o+'/v1/evaluations'},{href:o+'/a2a'},{href:o+'/mcp'}]},
    {anchor:o+'/v1/evaluations','service-desc':[{href:o+'/v1/openapi.json',type:'application/json'}],'service-meta':[{href:o+'/v1/contract',type:'application/json'}],'service-doc':[{href:o+'/',type:'text/html'}],status:[{href:o+'/healthz'}]}]},'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',req.method,{link});
  if(p==='/server.json')return response({$schema:'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json',name:'io.github.wheelerhubbell/whp-standing',description:'Verify signed JSON provenance and bounds through COPY/COMPOSE. Payment does not guarantee a Mark.',version:'1.0.0',repository:{url:'https://github.com/wheelerhubbell/WheelerHubbellPublishingStandingMark',source:'github'},remotes:[{type:'streamable-http',url:o+'/mcp'}]},'application/json',req.method);
  if(p==='/robots.txt')return response('User-agent: *\nAllow: /\nDisallow: /v1/purchases/\nDisallow: /v1/registry/\nSitemap: '+o+'/sitemap.xml\n','text/plain',req.method);
  if(p==='/sitemap.xml')return response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+['/','/v1/contract','/v1/verification',profilePath,...exposurePaths].map(x=>'<url><loc>'+o+x+'</loc></url>').join('')+'</urlset>','application/xml',req.method);
  if(p==='/llms.txt')return response('# '+SERVICE+'\n\n> '+CAPABILITY+'\n\nPublisher: '+PUBLISHER+'\n\nExact signed JSON COPY and identity-preserving COMPOSE only. Preserve source qualifications, unknowns, scope and jurisdiction. Does not establish external truth, domain authority, or execution permission.\n\n- [Contract and payment prerequisites]('+o+'/v1/contract)\n- [WHP Standing Profile]('+o+profilePath+')\n- [Independent verification]('+o+'/v1/verification)\n- [OpenAPI]('+o+'/v1/openapi.json)\n- [A2A Standing Mark carrier]('+o+'/.well-known/agent-card.json)\n- [MCP metadata]('+o+'/server.json)\n- [MCP]('+o+'/mcp)\n- [Bounded applicability: agent handoffs, APIs, MCP, approval records and recovered domain vocabulary]('+o+'/discovery/applicability.json)\n- [Exact-byte Mark handoff and recursive encounter]('+o+'/discovery/recursive-use.json)\n- [Current signed resolution]('+o+'/.well-known/standing-capability.json)\n- [Self-published capability catalog]('+o+'/discovery/provider-index.json)\n\nThe A2A carrier transports an exact existing Mark and canonical routes. It performs no evaluation, gives no opinion and determines no relevance.\n\nVerification of an existing Mark does not require another purchase. Payment funds an evaluation; it cannot purchase a Mark, truth or a favorable determination. A new evaluation requires independently admitted authority and owner-authorized payment. Standard x402 v2 exact EIP-3009 clients, including client-selected random nonces, are supported. No WHP-specific buyer authentication signature or client extension is required. No automatic forwarding or spending.\n\nThis text is a discovery aid, not authority, proof of registration, or a LIVE issuance claim.\n','text/plain',req.method);
  if(p==='/')return response('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>WHP Standing — Wheeler Hubbell Publishing</title><meta name="description" content="'+CAPABILITY+'"><link rel="canonical" href="'+o+'/"><link rel="api-catalog" href="'+o+'/.well-known/api-catalog"><script type="application/ld+json">'+JSON.stringify({'@context':'https://schema.org','@type':'Service',name:SERVICE,description:CAPABILITY,url:o,provider:{'@type':'Organization',name:PUBLISHER}})+'</script></head><body><h1>WHP Standing</h1><p>'+CAPABILITY+'</p><p>Wheeler Hubbell Publishing</p><p>Environment: '+service.trustBundle.profile_authorization.payload.environment+'</p><p>WHP Standing evaluates exact COPY and identity-preserving COMPOSE of admitted structured provenance. It does not establish arbitrary external-world truth, legal authority, or unobserved execution.</p><p><a href="/v1/contract">Purchase contract</a> · <a href="'+profilePath+'">WHP Standing Profile</a> · <a href="/v1/verification">Independent verification</a> · <a href="/v1/openapi.json">OpenAPI</a> · <a href="/server.json">MCP metadata</a></p><p>Payment does not determine standing. No LIVE issuance or external registration is claimed by this page.</p></body></html>','text/html; charset=utf-8',req.method,{link,'content-security-policy':"default-src 'none'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'"});
  return null;
}
