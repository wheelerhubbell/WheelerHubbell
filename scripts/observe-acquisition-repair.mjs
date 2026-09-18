// Explicit bounded unpaid observation. No wallet, secret access, settlement or issuance.
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {canonical,hash,hashBytes,keyId,parseStrict,demand} from '../src/canonical.mjs';
import {validateTrust} from '../src/authority.mjs';
import {evaluate} from '../src/evaluator.mjs';
import {ORIGIN,verifySourceCommitments} from './netlify-production-target.mjs';
const dir='evidence/acquisition-repair',trace=[];
await mkdir(dir,{recursive:true});
async function request(path,options={}){
  const response=await fetch(ORIGIN+path,{...options,redirect:'error',signal:AbortSignal.timeout(30000)}),raw=await response.text();
  trace.push({at:new Date().toISOString(),method:options.method??'GET',path,status:response.status,body_sha256:hashBytes(raw),request_id:response.headers.get('x-nf-request-id'),body:raw});
  return {response,raw};
}
const d=await request('/.well-known/whp-standing.json'),discovery=parseStrict(d.raw,1048576);
const repositoryBundle=parseStrict(await readFile('public/authority/trust-bundle.json','utf8'),1048576);
const rootPin=keyId(repositoryBundle.root_public_key);demand(discovery.root_pin===rootPin,'DEPLOYED_ROOT_MISMATCH');
const at=Math.floor(Date.now()/1000),trust=validateTrust(discovery.trust_bundle,rootPin,at);
const admission=parseStrict((await request('/authority/source-admission.json')).raw);
const source=admission.signed_record;
demand(source,'PUBLIC_SOURCE_ATTESTATION_REQUIRED');
const n=source.payload,example=parseStrict(await readFile('public/examples/submission.TEST.json','utf8'));
const s={version:'WHP-STANDING-SUBMISSION-v1',client_reference:'repair-unpaid-'+randomUUID(),buyer_key:example.buyer_key,
  profile:example.profile,object:{id:n.id,version:n.version,root:hash(n)},bounds:{scope:n.scope,jurisdiction:n.jurisdiction,valid_from:at-1,valid_until:at+300},requested_operation:'INFORM',nodes:[source],transitions:[]};
const decision=evaluate(s,discovery.trust_bundle,rootPin,at);
const post=body=>({method:'POST',headers:{'content-type':'application/json'},body});
await request('/v1/contract');
for(const body of ['{','{}',''])await request('/v1/evaluations',post(body));
await request('/v1/evaluations',{...post('{}'),headers:{'content-type':'text/plain'}});
const unpaid=await request('/v1/evaluations',post(canonical(s)));
demand(unpaid.response.status===402,'EXPECTED_UNPAID_BOUNDARY');
await writeFile(dir+'/production-observation.json',JSON.stringify({observed_at:new Date().toISOString(),origin:ORIGIN,
  baseline_main:'5e5a9dfc45e9b605d37bec433d4b5cfc874af612',deployment_commit_linkage:'Netlify current deploy has commit_ref:null; public behavior observed separately.',
  commitments:await verifySourceCommitments(),root_pin:rootPin,root_comparison:'Matches recovered repository public root; not independent institutional admission.',
  authority_certificates:[...trust.keys.entries()].map(([key_id,c])=>({key_id,...c})),
  object_checked:{submission:s,decision,scope:'The existing WHP-controlled protocol identity record only. Public TEST example buyer_key used as an unpaid probe identity, not as source authority.'},
  outside_object:{supplied:false,eligible_authorization_found:false,missing:'Existing-root admission of the actual outside SOURCE signing key for the exact object scope, jurisdiction, operations and validity; for COPY/COMPOSE, admission of a TRANSITION signer and an exact signed warrant. No outside object or signer is supplied, so no object-specific admission can be asserted.'},
  live_payment_executed:false,live_mark_issued:false,trace},null,2)+'\n');
console.log(JSON.stringify({object_outcome:decision.outcome,observations:trace.map(({method,path,status})=>({method,path,status})),live_payment_executed:false}));
