// Public machine transport for WHP Standing.
// The buyer does not perform a WHP-specific authentication signature before 402.
// Provenance/authority signatures inside the submitted object and the x402 wallet authorization
// remain distinct cryptographic objects with their existing semantics.

import openapiBase from '../public/openapi.json' with {type:'json'};
import resolutionSchema from '../schemas/discovery-resolution.schema.json' with {type:'json'};
import buyerManifest from '../public/buyer/manifest.json' with {type:'json'};
import {canonical,parseStrict,hash,seal,decode,encode,demand,Fault,exact} from './canonical.mjs';
import {observeNamespaces} from './namespace-authority.mjs';
import {validateSubmission} from './validation.mjs';
import {validateTrust,issuerAuthority,authorize} from './authority.mjs';
import {evaluate} from './evaluator.mjs';
import {validatePayment} from './payment.mjs';
import {contract as legacyContract,bazaar,profilePath,SERVICE,CAPABILITY,resolution as legacyResolution} from './discovery.mjs';
import {identity,RESOLUTION_PATH} from './protocol.mjs';
import {validateWire} from './wire-schema.mjs';
import {walletPayment,walletCheckout,PAYER_HEADER,WALLET_SIGNATURE_HEADER} from './wallet-checkout.mjs';
import {EVM_ADDRESS} from './payment.mjs';

const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
const json=(status,body,extra={})=>new Response(canonical(body)+'\n',{status,headers:{...headers,...extra}});
const result=bytes=>{const p=parseStrict(bytes,1048576).payload,s=p.commerce.settlement;return new Response(bytes,{status:200,headers:{...headers,'payment-response':encode({success:true,transaction:s.transaction,network:s.network,payer:s.payer})}});};
const purchaseId=(s,pin)=>hash({domain:'WHP-STANDING-PURCHASE-v1.1',root_pin:pin,client_reference:s.client_reference});

async function readBody(req){
  const reader=req.body?.getReader();if(!reader)return '';
  let size=0;const parts=[];
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>262144){await reader.cancel();throw new Fault('BODY_TOO_LARGE',413);}parts.push(Buffer.from(value));}
  try{return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts));}catch{throw new Fault('INVALID_UTF8');}
}

function publicBazaar(service){
  const b=bazaar(service);
  if(b?.info?.input)b.info.input.headers={};
  return b;
}

export function publicContract(service){
  const c=legacyContract(service);
  c.authentication={
    purchase:'NONE_BEYOND_X402_PAYMENT',
    retrieval:'OPAQUE_PURCHASE_CAPABILITY',
    review:'WHP-Client-Proof-v1 applies only to reviewer-authenticated review submissions; it is not required for purchase, 402 discovery, result retrieval or recovery.'
  };
  c.purchase.access_sequence=['SUBMIT_VALID_REQUEST','HTTP_402','X402_PAYMENT','RESULT_OR_PENDING'];
  c.purchase.whp_buyer_signature_required=false;
  c.purchase.direct_wallet={buyer_installation_required:false,guide_url:service.origin+'/direct-wallet.md',payer_header:PAYER_HEADER,signature_header:WALLET_SIGNATURE_HEADER,
    wallet_method:'eth_signTypedData_v4',instructions_pointer:'/extensions/whp-standing/info/wallet_checkout',
    sequence:'Submit the exact object with your existing wallet address. The 402 supplies the complete wallet request. Apply existing owner spending policy, sign that payment authorization, and resend the unchanged object with the returned wallet signature. No separate prepare endpoint, buyer login or client installation.',
    mcp:{tool:'whp_standing_evaluation',payer_argument:'payer',signature_argument:'wallet_signature',recover_tool:'whp_standing_recover'},
    authority:'Inspect wallet_checkout.eligibility before payment. An unadmitted source remains unadmitted; a negative assessment cannot produce a Mark.',
    compatibility:'EIP-712/EIP-3009 EOA wallets returning 65-byte signatures; Standard x402 v2 EIP-3009 clients with random nonces are supported; this wallet helper is optional.'};
  c.payment.required_extension=null;
  c.payment.nonce={source:'CLIENT_SELECTED_EIP3009_NONCE'};
  c.payment.generic_client_compatibility='Standard x402 v2 exact EIP-3009 clients. No WHP extension, buyer key, registration or client install is required.';
  c.payment.binding='The service atomically binds network, token, payer and nonce to the exact stored request before settlement; the wallet signature authorizes only the transfer.';
  c.authority_admission={class:'github-repository-control',manifest_path:'.well-known/standing-authority.json',schema_url:service.origin+'/namespace-authority.md',admission:'Bring the canonical public repository namespace and manifest hash. The controller publishes exact source/transition grants; the service verifies them over GitHub HTTPS. No source whitelist or per-buyer approval.',ceiling:'Repository control only. No institutional appointment or substantive truth claim.'};
  c.retrieval.identity='256-bit cryptographically random client_reference; root-bound opaque purchase capability. No buyer key.';
  c.purchase.buyer_client={...buyerManifest,url:service.origin+buyerManifest.path,guide_url:service.origin+'/buyer/README.md'};
  c.retrieval.lost_response='Use GET result or empty POST recovery with the durable purchase ID. Do not generate a second wallet authorization.';
  return c;
}

export function publicOpenapi(service){
  const api=structuredClone(openapiBase);
  api.servers=[{url:service.origin}];
  for(const [route,method] of [['/v1/evaluations','post'],['/v1/purchases/{purchase_id}/result','get'],['/v1/purchases/{purchase_id}/recover','post']]){
    const op=api.paths[route][method];delete op.security;delete op.responses?.['401'];
  }
  api.paths['/v1/contract'].get.responses['200'].description='Complete schema, authority, quote binding and independent buyer payment requirements; no WHP-specific buyer signature is required to reach 402.';
  api.paths['/v1/evaluations'].post.parameters.push(
    {name:PAYER_HEADER,in:'header',required:false,schema:{type:'string',pattern:'^0x[0-9a-fA-F]{40}$'},description:'Existing owner-authorized wallet address. On the unpaid request, asks for a complete eth_signTypedData_v4 payment request in the same 402 response; no buyer client installation.'},
    {name:WALLET_SIGNATURE_HEADER,in:'header',required:false,schema:{type:'string',pattern:'^0x[0-9a-fA-F]{128}(?:00|01|1[bBcC])$'},description:'The wallet payment signature returned for that 402, with PAYMENT-PAYER. Resend the original submission unchanged. Alternative to the complete base64 PAYMENT-SIGNATURE envelope; never send both.'});
  if(api.components?.securitySchemes?.ClientProof)api.components.securitySchemes.ClientProof.description='Reviewer-authentication proof for /v1/reviews only. It is not required for purchase, 402 discovery, result retrieval or recovery.';
  return api;
}

export function publicResolution(service){
  const prior=legacyResolution(service),payload=structuredClone(prior.payload);
  payload.service_contract={...payload.service_contract,sha256:hash(publicContract(service))};
  payload.openapi={...payload.openapi,sha256:hash(publicOpenapi(service))};
  const signed=seal('WHP-CAPABILITY-RESOLUTION-v1',payload,service.privateKey);
  const trust=validateTrust(service.trustBundle,service.rootPin,service.clock());
  authorize(signed,'WHP-CAPABILITY-RESOLUTION-v1','DISCOVERY',payload.authority_context,trust);
  validateWire(signed,resolutionSchema);
  return signed;
}

async function evaluateRoute(service,req){
  const u=new URL(req.url);let now=service.clock();
  demand(!u.search,'QUERY_NOT_SUPPORTED');
  demand((req.headers.get('content-type')??'').split(';')[0].trim()==='application/json','CONTENT_TYPE_REQUIRED',415);
  const raw=await readBody(req),s=validateSubmission(parseStrict(raw));
  const id=purchaseId(s,service.rootPin),requestHash=hash(s);
  const paymentHeader=req.headers.get('payment-signature'),walletSignature=req.headers.get(WALLET_SIGNATURE_HEADER),payer=req.headers.get(PAYER_HEADER);
  demand(!(paymentHeader&&walletSignature),'MULTIPLE_PAYMENT_FORMATS');
  if(payer!==null)demand(EVM_ADDRESS.test(payer),'PAYMENT_PAYER_INVALID');
  if(walletSignature!==null)demand(payer!==null&&/^0x[0-9a-fA-F]{128}(?:00|01|1[bBcC])$/.test(walletSignature),'WALLET_SIGNATURE_INVALID');
  let payment=paymentHeader?decode(paymentHeader,16384):null;
  let existing=await service.store.get(id);
  if(existing){demand(existing.request_hash===requestHash,'IDEMPOTENCY_CONFLICT',409);if(existing.state==='ISSUED')return result(existing.result_bytes);if(existing.state!=='QUOTED'){if(payment)demand(validatePayment(payment,existing.quote,now,{allowExpired:true})===existing.payment_key,'PURCHASE_ALREADY_BOUND',409);return service.progress(existing);}}
  const authorityEvidence=existing?.authority_evidence??await observeNamespaces(service,s);
  now=service.clock();
  const trust=validateTrust(service.trustBundle,service.rootPin,now),issuer=issuerAuthority(service.keyId,s.bounds.scope,s.bounds.jurisdiction,trust);
  const expires=Math.min(now+300,issuer.valid_until,trust.profile.valid_until,trust.bundle.status_snapshot.payload.valid_until);
  const quote=seal('WHP-STANDING-QUOTE-v1.1',{
    purchase_id:id,request_hash:requestHash,client_reference:s.client_reference,profile_hash:s.profile.sha256,issuer:trust.profile.issuer,
    environment:trust.profile.environment,issued_at:now,expires_at:expires,
    resource:{url:service.origin+'/v1/evaluations',description:'One bounded WHP Standing evaluation and durable retrieval',mimeType:'application/json'},
    payment_requirements:service.requirements,
    charge_policy:'One evaluation, regardless of outcome. No second charge for this purchase identity.'
  },service.privateKey);
  let row=await service.store.quote({id,buyer_key:'CAPABILITY-v1.1',client_reference:s.client_reference,request_hash:requestHash,state:'QUOTED',
    submission:s,authority_evidence:authorityEvidence,quote,trust_bundle:service.trustBundle,discovery_identity:identity(service.resolutionUrl,id,service.rootPin,trust.profile.environment),created_at:now});
  if(row.state==='ISSUED')return result((await service.store.get(id)).result_bytes);
  if(walletSignature)payment=walletPayment(row.quote,payer,walletSignature);
  if(row.state!=='QUOTED'){
    if(payment)demand(validatePayment(payment,row.quote,now,{allowExpired:true})===row.payment_key,'PURCHASE_ALREADY_BOUND',409);
    return service.progress(row);
  }
  demand(now<row.quote.payload.expires_at,'QUOTE_EXPIRED',409);
  if(!payment){
    const terms={x402Version:2,resource:row.quote.payload.resource,accepts:[row.quote.payload.payment_requirements],extensions:{'whp-standing':{info:{required:false,quote:row.quote},schema:{type:'object'}},bazaar:publicBazaar(service)}};
    // Keep the standard header bounded: the full wallet instructions and eligibility
    // observation are in the body. Both carry the exact same signed quote/terms.
    const decision=evaluate(s,row.trust_bundle,service.rootPin,now,row.authority_evidence);
    const paymentRequired=encode({x402Version:terms.x402Version,resource:terms.resource,accepts:terms.accepts});
    terms.purchase_id=row.id;terms.eligibility={outcome:decision.outcome,can_produce_mark:decision.outcome==='ESTABLISHED',failed_checks:decision.checks.filter(c=>!c.passed)};
    terms.recovery={result_url:service.origin+'/v1/purchases/'+id+'/result',recover_url:service.origin+'/v1/purchases/'+id+'/recover',additional_charge:false};
    if(payer)terms.extensions['whp-standing'].info.wallet_checkout=walletCheckout(service,row,payer,evaluate(s,row.trust_bundle,service.rootPin,now,row.authority_evidence));
    return json(402,terms,{'payment-required':paymentRequired});
  }
  const paymentKey=validatePayment(payment,row.quote,now);
  const observedBlock=await service.rail.startBlock();
  const verifiedPayment=await service.rail.verify(payment,row.quote.payload.payment_requirements);
  now=service.clock();
  demand(now<row.quote.payload.expires_at,'QUOTE_EXPIRED',409);
  validatePayment(payment,row.quote,now);
  const decision=evaluate(s,row.trust_bundle,service.rootPin,now,row.authority_evidence);
  demand(Buffer.byteLength(canonical({submission:s,decision,authority:row.trust_bundle,authority_evidence:row.authority_evidence,payment,quote:row.quote}))<=850000,'RESULT_CAPACITY_EXCEEDED',413);
  seal('WHP-SIGNER-PREFLIGHT-v1',{purchase_id:id,decision_hash:hash(decision)},service.privateKey);
  row=await service.store.reserve(id,requestHash,{payment_key:paymentKey,payment_payload:payment,discovery_verification:verifiedPayment.whp_discovery_evidence??null,decision,observed_block:observedBlock,scan_from:observedBlock,attempts:0,next_attempt_at:now});
  await service.hooks.afterPrepared?.(row);
  return service.progress(row);
}

async function purchaseRoute(service,req,path){
  const purchase=path.match(/^\/v1\/purchases\/([0-9a-f]{64})(\/result)?$/);
  if(req.method==='GET'&&purchase){
    const u=new URL(req.url);demand(!u.search,'QUERY_NOT_SUPPORTED');
    const row=await service.store.get(purchase[1]);demand(row,'PURCHASE_NOT_FOUND',404);
    if(row.state==='ISSUED')return result(row.result_bytes);
    return json(202,{purchase_id:row.id,state:row.state,recovery_path:'/v1/purchases/'+row.id+'/recover',additional_charge:false},{'retry-after':'5'});
  }
  const recover=path.match(/^\/v1\/purchases\/([0-9a-f]{64})\/recover$/);
  if(req.method==='POST'&&recover){
    const raw=await readBody(req);demand(raw==='','RECOVERY_BODY_MUST_BE_EMPTY');
    const row=await service.store.get(recover[1]);demand(row,'PURCHASE_NOT_FOUND',404);demand(row.state!=='QUOTED','PAYMENT_NOT_AUTHORIZED',409);
    return service.progress(row);
  }
  return null;
}

const MCP_VERSIONS=['2025-11-25','2025-06-18','2025-03-26'];
const mcpObject=(properties={},required=Object.keys(properties))=>({type:'object',properties,required,additionalProperties:false});
const mcpString=maxLength=>({type:'string',maxLength});
const mcpTools=[
  {name:'whp_standing_contract',description:'Discover WHP Standing: '+CAPABILITY+' Includes exact profile, schema, authority prerequisites and x402 payment contract.',inputSchema:mcpObject(),annotations:{readOnlyHint:true,idempotentHint:true,openWorldHint:false}},
  {name:'whp_standing_evaluation',description:'Submit the exact object and your existing wallet payer address. The 402 body supplies wallet_checkout: eligibility and the complete eth_signTypedData_v4 request. Your existing authorized wallet signs the payment under owner policy; retry this tool with the unchanged submission, same payer and returned wallet_signature. No WHP client install, login or additional buyer signature. Alternatively supply a complete base64 x402 payment_signature. Never send both signature formats.',inputSchema:mcpObject({submission_raw:mcpString(262144),payment_signature:mcpString(24000),payer:{type:'string',pattern:'^0x[0-9a-fA-F]{40}$'},wallet_signature:{type:'string',pattern:'^0x[0-9a-fA-F]{128}(?:00|01|1[bBcC])$'}},['submission_raw']),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:true}},
  {name:'whp_standing_result',description:'Retrieve the exact original WHP Standing Mark or negative assessment bytes by durable purchase ID, without another charge or WHP-specific signature.',inputSchema:mcpObject({purchase_id:{type:'string',pattern:'^[0-9a-f]{64}$'}}),annotations:{readOnlyHint:true,idempotentHint:true,openWorldHint:false}},
  {name:'whp_standing_recover',description:'Progress an already authorized pending purchase using its original durable payment. Supply only the purchase ID. Never sign another payment; if result retrieval says QUOTED, replay the original submission and identical saved wallet signature through whp_standing_evaluation.',inputSchema:mcpObject({purchase_id:{type:'string',pattern:'^[0-9a-f]{64}$'}}),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:true}}
];

async function mcpRoute(service,req){
  if(req.headers.has('origin')&&req.headers.get('origin')!==service.origin)return json(403,{jsonrpc:'2.0',error:{code:-32600,message:'Origin not allowed'}});
  if(req.method!=='POST')return new Response(null,{status:405,headers:{allow:'POST'}});
  if(!(req.headers.get('content-type')??'').startsWith('application/json'))return json(415,{jsonrpc:'2.0',error:{code:-32600,message:'JSON required'}});
  const accept=req.headers.get('accept')??'';if(!accept.includes('application/json')||!accept.includes('text/event-stream'))return json(406,{jsonrpc:'2.0',error:{code:-32600,message:'Accept application/json and text/event-stream'}});
  const proto=req.headers.get('mcp-protocol-version');if(proto&&!MCP_VERSIONS.includes(proto))return json(400,{jsonrpc:'2.0',error:{code:-32600,message:'Unsupported protocol version'}});
  let msg;try{const raw=await readBody(req);msg=parseStrict(raw,300000);}catch{return json(400,{jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid JSON'}});}
  if(!msg||typeof msg!=='object'||Array.isArray(msg)||msg.jsonrpc!=='2.0')return json(400,{jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}});
  if(!Object.hasOwn(msg,'id'))return new Response(null,{status:202});
  if(!['string','number'].includes(typeof msg.id)||!msg.method)return json(400,{jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}});
  const reply=value=>json(200,{jsonrpc:'2.0',id:msg.id,result:value});
  const error=(code,message)=>json(200,{jsonrpc:'2.0',id:msg.id,error:{code,message}});
  try{
    if(msg.method==='initialize')return reply({protocolVersion:MCP_VERSIONS.includes(msg.params?.protocolVersion)?msg.params.protocolVersion:MCP_VERSIONS[0],capabilities:{tools:{listChanged:false},resources:{subscribe:false,listChanged:false}},serverInfo:{name:SERVICE,version:'1.0.0'},instructions:'Read the WHP Standing contract before evaluation. Acquisition is submit -> 402 -> x402 payment; no WHP-specific buyer proof is required.'});
    if(msg.method==='ping')return reply({});
    if(msg.method==='tools/list')return reply({tools:mcpTools});
    const resources=[['/v1/contract','WHP Standing Evaluation contract'],[profilePath,'WHP Standing Profile'],['/v1/verification','WHP Standing Mark independent verification'],['/discovery/applicability.json','Bounded applicability and recovered domain vocabulary'],['/discovery/recursive-use.json','Caller-controlled Mark handoff and cold interpretation'],['/discovery/provider-index.json','Self-published capability catalog']].map(([p,name])=>({uri:service.origin+p,name,mimeType:'application/json'}));
    if(msg.method==='resources/list')return reply({resources});
    if(msg.method==='resources/read'){
      const uri=msg.params?.uri;if(!resources.some(r=>r.uri===uri))return error(-32002,'Resource not found');
      const response=await publicMachineRoute(service,new Request(uri))??await service.handle(new Request(uri));
      return reply({contents:[{uri,mimeType:'application/json',text:await response.text()}]});
    }
    if(msg.method!=='tools/call')return error(-32601,'Method not found');
    const name=msg.params?.name,a=msg.params?.arguments??{};
    if(name==='whp_standing_contract'){exact(a,[]);const data=publicContract(service);return reply({content:[{type:'text',text:canonical(data)}],structuredContent:data});}
    let response;
    if(name==='whp_standing_evaluation'){
      exact(a,['submission_raw',...['payment_signature','payer','wallet_signature'].filter(k=>Object.hasOwn(a,k))]);
      demand(typeof a.submission_raw==='string'&&Buffer.byteLength(a.submission_raw)<=262144,'INPUT_INVALID');
      const h={'content-type':'application/json'};if(a.payment_signature!==undefined){demand(typeof a.payment_signature==='string'&&a.payment_signature.length<=24000,'PAYMENT_HEADER_INVALID');h['payment-signature']=a.payment_signature;}
      if(a.payer!==undefined){demand(typeof a.payer==='string'&&EVM_ADDRESS.test(a.payer),'PAYMENT_PAYER_INVALID');h[PAYER_HEADER]=a.payer;}
      if(a.wallet_signature!==undefined){demand(typeof a.wallet_signature==='string'&&a.wallet_signature.length===132,'WALLET_SIGNATURE_INVALID');h[WALLET_SIGNATURE_HEADER]=a.wallet_signature;}
      response=await publicMachineRoute(service,new Request(service.origin+'/v1/evaluations',{method:'POST',headers:h,body:a.submission_raw}));
    }else if(name==='whp_standing_result'){
      exact(a,['purchase_id']);demand(/^[0-9a-f]{64}$/.test(a.purchase_id),'INPUT_INVALID');
      response=await purchaseRoute(service,new Request(service.origin+'/v1/purchases/'+a.purchase_id+'/result'),'/v1/purchases/'+a.purchase_id+'/result');
    }else if(name==='whp_standing_recover'){
      exact(a,['purchase_id']);demand(/^[0-9a-f]{64}$/.test(a.purchase_id),'INPUT_INVALID');
      response=await publicMachineRoute(service,new Request(service.origin+'/v1/purchases/'+a.purchase_id+'/recover',{method:'POST',body:''}));
    }else return error(-32602,'Unknown tool');
    const raw=await response.text(),data={http_status:response.status,headers:Object.fromEntries([...response.headers].filter(([k])=>['payment-required','payment-response','retry-after'].includes(k))),body_bytes:raw};
    return reply({content:[{type:'text',text:canonical(data)}],structuredContent:data,isError:response.status>=400&&response.status!==402});
  }catch{return error(-32602,'Invalid tool arguments');}
}

function rewriteLlms(text){
  return text
    .replaceAll('WHP-Client-Proof','WHP review proof')
    .replaceAll('whp-client-proof','review-only whp-client-proof')
    .replaceAll('authenticated GET','GET')
    .replaceAll('authenticated empty POST','empty POST');
}

export async function publicMachineRoute(service,req){
  try{
    const u=new URL(req.url),path=u.pathname;
    if(req.method==='POST'&&path==='/v1/evaluations')return await evaluateRoute(service,req);
    const purchase=await purchaseRoute(service,req,path);if(purchase)return purchase;
    if(req.method==='GET'&&path==='/v1/contract')return json(200,publicContract(service));
    if(req.method==='GET'&&(path==='/v1/openapi.json'||path==='/openapi.json'))return json(200,publicOpenapi(service));
    if(req.method==='GET'&&path===RESOLUTION_PATH)return json(200,publicResolution(service));
    if(path==='/mcp')return mcpRoute(service,req);
    if(req.method==='GET'&&path==='/llms.txt'){
      const original=await service.handle(req);return new Response(rewriteLlms(await original.text())+'\nDirect wallet acquisition: POST the object with PAYMENT-PAYER (or MCP payer). The 402 body supplies the exact eth_signTypedData_v4 request for your existing authorized wallet. Resend the unchanged object with PAYMENT-WALLET-SIGNATURE (or MCP wallet_signature). No WHP client install, login or separate preparation request. Check exact-object eligibility and enforce existing owner spending policy before signing. Recovery uses the original purchase ID and saved payment.\nOptional reference buyer: '+service.origin+'/buyer/README.md (download and SHA-256 in /v1/contract purchase.buyer_client).\n',{status:original.status,statusText:original.statusText,headers:original.headers});
    }
    return null;
  }catch(e){
    if(e instanceof Fault)return json(e.status,{error:{code:e.code,path:e.path}});
    return json(503,{error:{code:'SERVICE_UNAVAILABLE',retryable:true}});
  }
}
