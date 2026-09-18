// A release cannot use TEST receipts or replace a two-agent execution with a 402 probe.
// Read-only: requires the captured execution, exact records and an independent RPC.
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {hash,hashBytes,demand,parseStrict} from '../src/canonical.mjs';
import {validateTrust,authorize} from '../src/authority.mjs';
import {validateWire} from '../src/wire-schema.mjs';
import resolutionSchema from '../schemas/discovery-resolution.schema.json' with {type:'json'};
import {pythonVerifier} from '../verify/python-verifier.mjs';
import {releaseSource} from './release-source.mjs';
async function fetchDocument(url){
  const u=new URL(url);demand(u.protocol==='https:'&&!u.username&&!u.password&&!u.hash,'HTTPS_EVIDENCE_URL_REQUIRED');
  const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(20000)});demand(response.ok,'CURRENT_EVIDENCE_UNAVAILABLE');
  const raw=await response.text();return {raw,document:parseStrict(raw,1048576)};
}
async function freshRegistry(bytes,pin){
  const mark=parseStrict(bytes,1048576),p=mark.payload;
  // Authenticate the immutable Mark before following its discovery location.
  authorize(mark,'WHP-STANDING-MARK-v1.1','ISSUER',p.submission.bounds,validateTrust(p.authority,pin,p.issued_at));
  demand(p.discovery.root_key_id===pin,'DISCOVERY_ROOT_BINDING');
  const {document:resolution}=await fetchDocument(p.discovery.resolution_url);validateWire(resolution,resolutionSchema);
  const r=resolution.payload,at=Math.floor(Date.now()/1000),trust=validateTrust(r.trust_bundle,pin,at);
  authorize(resolution,'WHP-CAPABILITY-RESOLUTION-v1','DISCOVERY',r.authority_context,trust);
  demand(['root_key_id','capability_id','capability_class','resolution_id'].every(k=>r[k]===p.discovery[k]),'RESOLUTION_IDENTITY_MISMATCH');
  demand(r.environment===p.environment&&r.environment==='LIVE'&&r.issuer===trust.profile.issuer,'RESOLUTION_ENVIRONMENT_OR_ISSUER');
  demand(r.observed_at<=at+30&&at<r.valid_until&&r.valid_until<=r.observed_at+300&&r.valid_until<=trust.bundle.status_snapshot.payload.valid_until,'RESOLUTION_STALE');
  const origin=new URL(r.service_origin);demand(origin.protocol==='https:'&&origin.origin===r.service_origin,'CURRENT_SERVICE_ORIGIN');
  demand(r.registry_template.split('{purchase_id}').length===2,'REGISTRY_TEMPLATE');
  const url=r.registry_template.replace('{purchase_id}',p.purchase_id);demand(new URL(url).origin===origin.origin,'REGISTRY_ORIGIN');
  // The independent verifier below checks the refreshed snapshot signature,
  // current namespace observations, exact result binding and finalized payment.
  return (await fetchDocument(url)).raw;
}
try{
  const dir=process.env.WHP_LIVE_CHAIN_DIR,pin=process.env.WHP_RELEASE_ROOT_PIN,rpc=process.env.WHP_RELEASE_RPC_URL;
  demand(dir&&pin&&rpc,'LIVE_CHAIN_EVIDENCE_AND_OWNER_TRUST_POLICY_REQUIRED');
  const [a,b,raw]=await Promise.all(['A.mark.json','B.mark.json','execution.json'].map(n=>readFile(join(dir,n),'utf8')));
  const receipt=JSON.parse(raw),pa=JSON.parse(a).payload,pb=JSON.parse(b).payload;
  demand(receipt.version==='WHP-LIVE-CHAIN-EXECUTION-v1'&&receipt.environment==='LIVE','LIVE_EXECUTION_REQUIRED');
  demand(receipt.consumer_sha256===hashBytes(await readFile(new URL('./cold-purchaser.mjs',import.meta.url))),'EXECUTED_CONSUMER_SOURCE_REQUIRED');
  demand(receipt.service_candidate&&hash(receipt.service_candidate)===hash(await releaseSource()),'EXECUTED_SERVICE_CANDIDATE_REQUIRED');
  demand(receipt.a.mark_sha256===hashBytes(a)&&receipt.b.mark_sha256===hashBytes(b),'EXECUTION_MARK_BINDING');
  demand(receipt.b.encountered_mark_sha256===hashBytes(a)&&receipt.a.wallet_calls===1&&receipt.b.wallet_calls===1,'RECURSIVE_EXECUTION_REQUIRED');
  for(const [x,p] of [[receipt.a,pa],[receipt.b,pb]]){
    demand(x.clean_environment===true&&x.provider_prior_configuration===false&&x.whp_client_installed===false,'COLD_HTTP_EXECUTION_REQUIRED');
    const q=x.milestones?.quoted,r=x.milestones?.verified_result;
    demand(Array.isArray(x.trace)&&Number.isSafeInteger(q?.trace_index)&&Number.isSafeInteger(r?.trace_index)&&q.trace_index>=0&&r.trace_index>q.trace_index,'DURABLE_EXECUTION_MILESTONES_REQUIRED');
    const first=x.trace[q.trace_index],last=x.trace[r.trace_index],origin=new URL(p.commerce.quote.payload.resource.url).origin;
    demand(first?.method==='POST'&&first.status===402&&first.url===p.commerce.quote.payload.resource.url,'INITIAL_402_REQUIRED');
    demand(q.purchase_id===p.purchase_id&&r.purchase_id===p.purchase_id&&r.mark_sha256===x.mark_sha256,'EXECUTION_PURCHASE_BINDING');
    const terminal=last&&(last.method==='POST'&&[p.commerce.quote.payload.resource.url,origin+'/v1/purchases/'+p.purchase_id+'/recover'].includes(last.url)||last.method==='GET'&&last.url===origin+'/v1/purchases/'+p.purchase_id+'/result');
    demand(terminal&&last.status===200,'VERIFIED_RESULT_OR_RECOVERY_200_REQUIRED');
  }
  demand(receipt.b.provider_url_source==='ENCOUNTERED_MARK'&&receipt.b.relevance_source==='OWN_TASK','INDEPENDENT_TASK_AND_DISCOVERY_REQUIRED');
  demand(pa.environment==='LIVE'&&pb.environment==='LIVE'&&pa.purchase_id!==pb.purchase_id&&pa.object.id!==pb.object.id,'DISTINCT_LIVE_PURCHASES_REQUIRED');
  demand(pa.commerce.assessment_paid_by.toLowerCase()!==pb.commerce.assessment_paid_by.toLowerCase(),'SEPARATE_OWNER_WALLETS_REQUIRED');
  demand(pa.submission.nodes.every(a=>pb.submission.nodes.every(b=>a.protected.key_id!==b.protected.key_id)),'INDEPENDENT_SOURCE_KEYS_REQUIRED');
  const [ar,br]=await Promise.all([freshRegistry(a,pin),freshRegistry(b,pin)]);
  const verifier=pythonVerifier({rootPin:pin,allowTest:false,rpcUrl:rpc,python:process.env.WHP_TEST_PYTHON??'python3'}),at=Math.floor(Date.now()/1000);
  const reports=await Promise.all([verifier(a,ar,at),verifier(b,br,at)]);
  demand(reports.every(r=>r.technical_live_issuance_verified===true),'TWO_FINALIZED_INDEPENDENTLY_VERIFIED_LIVE_MARKS_REQUIRED');
  console.log(JSON.stringify({release_gate_passed:true,receipt_sha256:hashBytes(raw),service_candidate_sha256:receipt.service_candidate.sha256,fresh_registry_sha256:[hashBytes(ar),hashBytes(br)],purchase_ids:[pa.purchase_id,pb.purchase_id],live_chain_records_verified:true,cold_process_observation:'Captured execution receipt and orchestrator source commitment; neither independently attests remote deployed code.',outside_demand_established:false}));
}catch(e){console.error(JSON.stringify({release_gate_passed:false,error:e.code??e.message,production_completion:false}));process.exitCode=1;}
