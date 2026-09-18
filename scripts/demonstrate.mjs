import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {setup,NOW} from '../test/fixtures.mjs';import {nodeServer} from '../src/server.mjs';import {BuyerJournal} from '../src/buyer-journal.mjs';import {StandingBuyer,Eip1193Signer} from '../src/buyer.mjs';import {pythonVerifier} from '../verify/python-verifier.mjs';import {PROFILE_HASH} from '../src/profile.mjs';import {canonical,hashBytes,demand} from '../src/canonical.mjs';
const run=promisify(execFile),destination=resolve(process.argv[2]??'evidence/demonstration');await mkdir(destination,{recursive:true});
const runtime=await mkdtemp(join(tmpdir(),'whp-standing-demo-')),dbfile=join(runtime,'service.sqlite'),journalfile=join(runtime,'buyer.sqlite');
const x=await setup({filename:dbfile}),server=nodeServer(x.service);await new Promise(r=>server.listen(0,'127.0.0.1',r));x.service.origin='http://127.0.0.1:'+server.address().port;
let signatures=0;const trace=[];const wallet=new Eip1193Signer({request:async({method,params})=>{demand(method==='eth_signTypedData_v4','WRONG_SIGNING_METHOD');signatures++;return '0x'+'11'.repeat(64)+'1b';}});
const policy={environment:'TEST',origin:x.service.origin,root_pin:x.f.rootPin,profile_hash:PROFILE_HASH,network:x.f.requirements.network,asset:x.f.requirements.asset,pay_to:x.f.requirements.payTo,payer:'0x'+'33'.repeat(20),asset_name:'USDC',asset_version:'2',max_per_purchase:'1000000',max_total:'1000000'};
const journal=new BuyerJournal(journalfile),agent=new StandingBuyer({policy,privateKey:x.f.buyer.privateKey,paymentSigner:wallet,journal,clock:()=>NOW,
  verifyResult:pythonVerifier({rootPin:x.f.rootPin,allowTest:true}),fetchImpl:async(url,options)=>{const r=await fetch(url,options);trace.push({method:options.method,path:new URL(url).pathname,payment_authorization_present:!!options.headers['payment-signature'],http_status:r.status});return r;}});
let closed=false;
try{
  const first=await agent.purchase(x.f.submission),retrieved=await agent.retrieve(x.f.submission);demand(first.result_bytes===retrieved.result_bytes,'RETRIEVAL_CHANGED_BYTES');
  const registry=journal.get(first.purchase_id).registry;
  journal.close();await new Promise(r=>server.close(r));await x.store.close();closed=true;
  // Independent OS process reads committed bytes after the writer connection and HTTP server close.
  const {stdout:restarted}=await run(process.execPath,[new URL('../test/helpers/read-store.mjs',import.meta.url).pathname,dbfile,first.purchase_id],{maxBuffer:2097152});
  demand(restarted===first.result_bytes,'PROCESS_RESTART_CHANGED_BYTES');
  const markpath=join(destination,'TEST-standing-mark.json'),registrypath=join(destination,'TEST-registry-snapshot.json');
  await writeFile(markpath,first.result_bytes);await writeFile(registrypath,registry);
  await writeFile(join(destination,'TEST-submission.json'),canonical(x.f.submission)+'\n');
  await writeFile(join(destination,'TEST-public-trust.json'),canonical({environment:'TEST',root_pin:x.f.rootPin,root_public_key:x.f.trustBundle.root_public_key,trust_bundle:x.f.trustBundle,note:'Generated test identity. This is not a WHP institutional root or live issuance.'})+'\n');
  const {stdout:independent}=await run('python3',[new URL('../verify/verify_mark.py',import.meta.url).pathname,markpath,'--root-pin',x.f.rootPin,'--allow-test','--registry',registrypath,'--at',String(NOW)],{maxBuffer:1048576});
  await writeFile(join(destination,'independent-verification.json'),independent);
  const receipt={artifact:'WHP Standing v1 executable demonstration',execution_recorded_at:new Date().toISOString(),fixture_clock:new Date(NOW*1000).toISOString(),
    environment:'TEST',live_completion:false,purchase_id:first.purchase_id,mark_id:JSON.parse(first.result_bytes).payload.mark_id,
    root_pin:x.f.rootPin,mark_sha256:hashBytes(first.result_bytes),registry_sha256:hashBytes(registry),
    real_http_server_used:true,independent_python_verifier_executed:true,byte_identical_authenticated_retrieval:true,separate_process_durable_retrieval:true,
    payment_wallet_signer:'SIMULATED EIP-1193 provider returning a format-valid fixture signature, not ECDSA wallet signing',
    settlement_rail:'SIMULATED payment rail; no blockchain or real funds',signer_invocations:signatures,settlement_calls:x.rail.settleCalls,simulated_transfers:x.rail.transfers,
    chain_requests:0,actual_funds_moved:'0',private_keys_exported:false,trace,
    not_executed:['Real buyer payment','Institutional root and profile ratification','Live EIP-3009 wallet signature verification','Live facilitator integration','Live chain finality','PostgreSQL integration','Netlify deployment','External independent security audit']};
  await writeFile(join(destination,'execution-record.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt,null,2));
}finally{if(!closed){try{journal.close();}catch{}await new Promise(r=>server.close(r));await x.store.close();}await rm(runtime,{recursive:true,force:true});}
