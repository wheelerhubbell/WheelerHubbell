import submissionSchema from '../schemas/submission.schema.json' with {type:'json'};
import resultSchema from '../schemas/result.schema.json' with {type:'json'};
import trustSchema from '../schemas/trust-bundle.schema.json' with {type:'json'};
import requirementsSchema from '../schemas/payment-requirements.schema.json' with {type:'json'};
import openapi from '../public/openapi.json' with {type:'json'};
const publicSchemas={'/schemas/submission.schema.json':submissionSchema,'/schemas/result.schema.json':resultSchema,'/schemas/trust-bundle.schema.json':trustSchema,'/schemas/payment-requirements.schema.json':requirementsSchema};
import { canonical, parseStrict, hash, hashBytes, seal, openSeal, keyId, publicDer, decode, encode, demand, Fault, randomHex, exact } from './canonical.mjs';
import { validateSubmission } from './validation.mjs';
import { validateTrust, issuerAuthority, liveAuthorityIntact } from './authority.mjs';
import {observeNamespaces} from './namespace-authority.mjs';
import { evaluate } from './evaluator.mjs';
import {assembleResult as assembleLegacyResult} from '../legacy/v1/src/mark.mjs';
import { assembleResult } from './mark.mjs';
import { profile, PROFILE_HASH } from './profile.mjs';
import { validatePayment, validateRequirements, HEX32 } from './payment.mjs';
import {discoveryRoute,contract,profilePath,livePaymentDestination,bazaar} from './discovery.mjs';
import {identity,RESOLUTION_PATH} from './protocol.mjs';
import {mcpRoute} from './mcp.mjs';
import {a2aRoute} from './carrier.mjs';

const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
const json=(status,body,extra={})=>new Response(canonical(body)+'\n',{status,headers:{...headers,...extra}});
const result=bytes=>{const p=parseStrict(bytes,1048576).payload,s=p.commerce.settlement;return new Response(bytes,{status:200,headers:{...headers,'payment-response':encode({success:true,transaction:s.transaction,network:s.network,payer:s.payer})}});};
export const purchaseId=(s,pin)=>hash({domain:'WHP-STANDING-PURCHASE-v1.1',root_pin:pin,client_reference:s.client_reference});
export function clientProof(privateKey,method,path,body,at){return encode(seal('WHP-CLIENT-PROOF-v1',{method,path,body_hash:hashBytes(body),issued_at:at,expires_at:at+120,nonce:randomHex(16)},privateKey));}
function authenticate(req,pub,body,now){
  const e=decode(req.headers.get('whp-client-proof')??'',4096);
  const p=openSeal(e,'WHP-CLIENT-PROOF-v1',pub);
  exact(p,['body_hash','expires_at','issued_at','method','nonce','path']);
  const u=new URL(req.url);
  demand(p.method===req.method&&p.path===u.pathname+u.search&&p.body_hash===hashBytes(body),'CLIENT_PROOF_BINDING',401);
  demand(Number.isSafeInteger(p.issued_at)&&Number.isSafeInteger(p.expires_at)&&p.issued_at<=now+30&&p.expires_at>now&&p.expires_at-p.issued_at<=120&&p.expires_at>p.issued_at,'CLIENT_PROOF_EXPIRED',401);
  demand(typeof p.nonce==='string'&&/^[0-9a-f]{32}$/.test(p.nonce),'CLIENT_PROOF_NONCE',401);
}
async function readBody(req){const reader=req.body?.getReader();if(!reader)return '';let size=0;const parts=[];
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>262144){await reader.cancel();throw new Fault('BODY_TOO_LARGE',413);}parts.push(Buffer.from(value));}
  try{return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts));}catch{throw new Fault('INVALID_UTF8');}}

export class StandingService {
  constructor({store,rail,privateKey,trustBundle,rootPin,origin,requirements,resolutionUrl=null,catalogUrl=null,clock=()=>Math.floor(Date.now()/1000),hooks={}}) {
    demand(/^https:\/\//.test(origin)||/^http:\/\/127\.0\.0\.1(?::[0-9]+)?$/.test(origin),'SERVICE_ORIGIN_INVALID',503);
    demand(!new URL(origin).search&&new URL(origin).pathname==='/'&&!new URL(origin).username,'SERVICE_ORIGIN_INVALID',503);
    this.store=store;this.rail=rail;this.privateKey=privateKey;this.trustBundle=trustBundle;this.rootPin=rootPin;this.origin=origin.replace(/\/$/,'');this.requirements=requirements;this.clock=clock;this.hooks=hooks;
    this.keyId=keyId(publicDer(privateKey));this._resolutionUrl=resolutionUrl;this.catalogUrl=catalogUrl;
    const trust=validateTrust(trustBundle,rootPin,clock());validateRequirements(requirements);
    demand(trust.keys.get(this.keyId)?.roles.includes('ISSUER')&&trust.keys.get(this.keyId)?.roles.includes('REGISTRY')&&trust.keys.get(this.keyId)?.roles.includes('DISCOVERY'),'ISSUER_REGISTRY_DISCOVERY_AUTHORITY_REQUIRED',503);
    demand(requirements.scheme==='exact'&&requirements.extra.assetTransferMethod==='eip3009'&&requirements.extra.paymentFlow==='authorization','PAYMENT_SCHEME_UNSUPPORTED',503);
    demand(/^eip155:[1-9][0-9]*$/.test(requirements.network)&&/^0x[0-9a-f]{40}$/.test(requirements.asset)&&/^0x[0-9a-f]{40}$/.test(requirements.payTo)&&/^[1-9][0-9]*$/.test(requirements.amount),'PAYMENT_CONFIG_INVALID',503);
    if(trust.profile.environment==='LIVE')livePaymentDestination(requirements);
    demand(trust.profile.environment!=='LIVE'||(origin.startsWith('https://')&&trust.profile.issuer==='Wheeler Hubbell Publishing'&&rail.constructor.name==='EvmRail'),'LIVE_CONFIGURATION_INVALID',503);
  }
  get resolutionUrl(){return this._resolutionUrl??this.origin+RESOLUTION_PATH;}
  async handle(req){try{return await this.route(req);}catch(e){
    if(e instanceof Fault)return json(e.status,{error:{code:e.code,path:e.path}});
    // Never reflect internal DB errors, provider URLs, secret material or stack traces.
    return json(503,{error:{code:'SERVICE_UNAVAILABLE',retryable:true}});
  }}
  async route(req){const u=new URL(req.url),now=this.clock(),path=u.pathname;
    const discovered=await discoveryRoute(this,req);if(discovered)return discovered;
    if(path==='/a2a')return a2aRoute(this.origin,req);
    if(path==='/mcp')return mcpRoute(this,req);
    if(req.method==='GET'&&['/schemas/submission.schema.json','/schemas/result.schema.json','/schemas/trust-bundle.schema.json','/schemas/payment-requirements.schema.json'].includes(path)){
      return json(200,publicSchemas[path]);}
    if(req.method==='GET'&&path==='/v1/openapi.json')return json(200,{...openapi,servers:[{url:this.origin}]});
    if(req.method==='GET'&&path==='/healthz')return json(200,{service:'WHP Standing',version:'1.0.0',live_completion_proven:false});
    if(req.method==='GET'&&path==='/.well-known/whp-standing.json')return json(200,{
      resolution_url:this.resolutionUrl,capability_id:'urn:whp:standing:capability:1',contract_url:this.origin+'/v1/contract',verification_url:this.origin+'/v1/verification',profile_url:this.origin+profilePath,mcp_url:this.origin+'/mcp',
      service:'WHP Standing',version:'1.0.0',environment:this.trustBundle.profile_authorization.payload.environment,
      issuer:this.trustBundle.profile_authorization.payload.issuer,root_public_key:this.trustBundle.root_public_key,root_pin:this.rootPin,
      issuer_certificate:this.trustBundle.certificates.find(e=>keyId(e.payload.public_key)===this.keyId),
      profile:profile(),profile_authorization:this.trustBundle.profile_authorization,trust_bundle:this.trustBundle,
      evaluation_url:this.origin+'/v1/evaluations',registry_url_template:this.origin+'/v1/registry/{purchase_id}',
      review_url:this.origin+'/v1/reviews',retrieval_charge:'0',payment_protocol:'x402-v2',
      required_extension:null,payment_binding:'Standard x402 v2 exact EIP-3009, client-selected nonce. Durable atomic association to the exact submitted request; wallet authorization establishes payment only.',
      request_limit_bytes:262144,max_nodes:64,max_transitions:64,
      input_schema:'/schemas/submission.schema.json',result_schema:'/schemas/result.schema.json',
      completion_claim:'No claim of live issuance follows from discovery or health.'});
    if(req.method==='GET'&&path==='/v1/profile')return json(200,{profile:profile(),sha256:PROFILE_HASH,authorization:this.trustBundle.profile_authorization});
    if(path==='/v1/evaluations'||path.startsWith('/v1/purchases/')){
      const {publicMachineRoute}=await import('./public-machine.mjs');return await publicMachineRoute(this,req);
    }
    const registry=path.match(/^\/v1\/registry\/([0-9a-f]{64})$/);
    if(req.method==='GET'&&registry){const row=await this.store.get(registry[1]);demand(row?.state==='ISSUED','REGISTRY_ENTRY_NOT_FOUND',404);const parsed=parseStrict(row.result_bytes,1048576);let events=await this.store.events(row.id);
      demand(parsed.payload.version==='WHP-STANDING-RESULT-v1.1','LEGACY_CURRENT_STATUS_REQUIRES_MATCHING_TRUST_EPOCH',409);
      let last=events.at(-1).payload,authorityEvidence=[];
      if(last.status==='ACTIVE'&&now<parsed.payload.expires_at){
        try{authorityEvidence=await observeNamespaces(this,parsed.payload.submission);}catch{}
      }
      // Current observations belong to this snapshot, never the immutable issuance record.
      events=await this.store.events(row.id);last=events.at(-1).payload;
      const observedAt=this.clock(),currentTrust=validateTrust(this.trustBundle,this.rootPin,observedAt);issuerAuthority(this.keyId,row.submission.bounds.scope,row.submission.bounds.jurisdiction,currentTrust);
      demand(currentTrust.keys.get(this.keyId)?.roles.includes('REGISTRY'),'REGISTRY_AUTHORITY_REQUIRED',503);
      let status=last.status;if(status==='ACTIVE'&&observedAt>=parsed.payload.expires_at)status='EXPIRED';
      else if(status==='ACTIVE'&&!liveAuthorityIntact(parsed,currentTrust,authorityEvidence))status='LIMITED';
      if(status!=='ACTIVE')authorityEvidence=[];
      return json(200,seal('WHP-REGISTRY-SNAPSHOT-v1',{purchase_id:row.id,result_hash:row.result_hash,mark_id:parsed.payload.mark_id,status,
        observed_at:observedAt,valid_until:Math.min(observedAt+300,...authorityEvidence.map(e=>e.payload.observed_at+300),currentTrust.bundle.status_snapshot.payload.valid_until,currentTrust.profile.valid_until,currentTrust.keys.get(this.keyId).valid_until),events,trust_bundle:this.trustBundle,authority_evidence:authorityEvidence},this.privateKey));}
    if(req.method==='POST'&&path==='/v1/reviews') {
      const raw=await readBody(req),r=parseStrict(raw);exact(r,['client_reference','evidence_hashes','purchase_id','reason','reviewer_key']);
      demand(/^[0-9a-f]{64}$/.test(r.purchase_id)&&typeof r.reason==='string'&&r.reason.length>0&&r.reason.length<=8192&&Array.isArray(r.evidence_hashes)&&r.evidence_hashes.length<=64&&r.evidence_hashes.every(h=>/^[0-9a-f]{64}$/.test(h)),'REVIEW_INVALID');
      demand(typeof r.client_reference==='string'&&/^[A-Za-z0-9_-]{16,96}$/.test(r.client_reference),'REVIEW_REFERENCE_INVALID');
      authenticate(req,r.reviewer_key,raw,now);const old=await this.store.get(r.purchase_id);demand(old?.state==='ISSUED','REGISTRY_ENTRY_NOT_FOUND',404);
      const stored=await this.store.review({review_id:hash({reviewer:r.reviewer_key,reference:r.client_reference}),purchase_id:r.purchase_id,request:r,received_at:now,status:'RECEIVED_NOT_ADJUDICATED'});
      return json(201,seal('WHP-REVIEW-RECEIPT-v1',stored,this.privateKey));
    }
    return json(404,{error:{code:'NOT_FOUND'}});
  }
  async progress(initial) {
    if(initial.state==='ISSUED')return result((await this.store.get(initial.id)).result_bytes);
    const id=initial.id,owner=randomHex(16),now=this.clock();
    if(!await this.store.lease(id,owner,now))return json(202,{purchase_id:id,state:'IN_PROGRESS',additional_charge:false},{'retry-after':'5'});
    try {
      let row=await this.store.get(id);
      if(row.state==='PREPARED')row=await this.store.update(id,owner,r=>({...r,state:'SETTLING'}));
      if(row.state==='SETTLING') {
        let proof=await this.rail.reconcile(row,now);
        if(proof?.scan_only){row=await this.store.update(id,owner,r=>({...r,scan_from:proof.next_scan_from}));proof=null;}
        if(!proof&&!row.transaction_hint&&now>=row.next_attempt_at&&BigInt(now)<BigInt(row.payment_payload.payload.authorization.validBefore)) {
          row=await this.store.update(id,owner,r=>({...r,attempts:r.attempts+1,next_attempt_at:now+30}));
          await this.hooks.beforeSettle?.(row);
          let settled=null;
          try{settled=await this.rail.settle(row.payment_payload,row.quote.payload.payment_requirements);}catch{}
          await this.hooks.afterSettle?.(row,settled);
          if(settled?.whp_discovery_evidence)row=await this.store.update(id,owner,r=>({...r,discovery_settlement:settled.whp_discovery_evidence}));
          if(settled&&settled.network===row.payment_payload.accepted.network&&HEX32.test(settled.transaction??'')&&(!settled.payer||settled.payer.toLowerCase()===row.payment_payload.payload.authorization.from.toLowerCase()))
            row=await this.store.update(id,owner,r=>({...r,transaction_hint:settled.transaction.toLowerCase()}));
          proof=await this.rail.reconcile(row,now);
          if(proof?.scan_only){const next=proof.next_scan_from;row=await this.store.update(id,owner,r=>({...r,scan_from:next}));proof=null;}
        }
        if(!proof)return json(202,{purchase_id:id,state:'RECONCILING',additional_charge:false,
          instruction:'Recover this purchase using the stored authorization. Do not create or sign another payment for it.'},{'retry-after':'30'});
        demand(proof.environment===row.trust_bundle.profile_authorization.payload.environment,'SETTLEMENT_ENVIRONMENT_MISMATCH',503);
        demand(proof.network===row.payment_payload.accepted.network&&proof.asset?.toLowerCase()===row.payment_payload.accepted.asset.toLowerCase()&&proof.payer.toLowerCase()===row.payment_payload.payload.authorization.from.toLowerCase()&&proof.pay_to.toLowerCase()===row.payment_payload.accepted.payTo.toLowerCase()&&proof.amount===row.payment_payload.accepted.amount&&proof.nonce===row.payment_payload.payload.authorization.nonce,'SETTLEMENT_IDENTITY_MISMATCH',503);
        row=await this.store.update(id,owner,r=>({...r,state:'SETTLED',settlement:proof,issued_at:now}));
        await this.hooks.afterDurableSettlement?.(row);
      }
      const bytes=(row.submission.version==='WHP-STANDING-SUBMISSION-v1'?assembleLegacyResult:assembleResult)(row,this.privateKey,this.rootPin),parsed=parseStrict(bytes,1048576);
      const event=seal('WHP-REGISTRY-EVENT-v1',{purchase_id:id,sequence:0,previous_hash:null,result_hash:hashBytes(bytes),
        mark_id:parsed.payload.mark_id,status:parsed.payload.mark_id?'ACTIVE':'ASSESSED_NO_MARK',at:row.issued_at,reason:'Original issuance',command:null},this.privateKey);
      await this.hooks.beforePersistResult?.(bytes);
      const durable=await this.store.finish(id,owner,bytes,event);
      await this.hooks.afterPersistResult?.(durable);
      return result(durable);
    }finally{await this.store.release(id,owner);}
  }
  async applyRegistryCommand(command) {
    const c=openSeal(command,'WHP-REGISTRY-COMMAND-v1',this.trustBundle.root_public_key);
    exact(c,['at','expected_previous_hash','purchase_id','reason','status']);
    demand(['ACTIVE','SUSPENDED','WITHDRAWN','SUPERSEDED','DISPUTED','LIMITED'].includes(c.status)&&typeof c.reason==='string'&&c.reason.length>0&&c.at<=this.clock()+30,'REGISTRY_COMMAND_INVALID');
    return this.store.appendEvent(c.purchase_id,(last,seq,prev)=>{
      demand(prev===c.expected_previous_hash,'REGISTRY_CONCURRENT_CHANGE',409);
      demand(last&&last.payload.mark_id,'NO_MARK_TO_CHANGE',409);
      demand(!['WITHDRAWN','SUPERSEDED'].includes(last.payload.status),'REGISTRY_TERMINAL_STATUS',409);
      demand(c.at>=last.payload.at,'REGISTRY_TIME_REVERSED',409);
      return seal('WHP-REGISTRY-EVENT-v1',{purchase_id:c.purchase_id,sequence:seq,previous_hash:prev,
        result_hash:last.payload.result_hash,mark_id:last.payload.mark_id,status:c.status,at:c.at,reason:c.reason,command},this.privateKey);
    });
  }
}
