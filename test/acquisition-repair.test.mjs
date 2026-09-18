// Targeted new connections only. No inherited suite, propagation, LIVE signer or chain calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import {registerHooks} from 'node:module';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {setup,NOW,FakeRail} from './fixtures.mjs';
import {canonical,hash,hashBytes,parseStrict,clone,decode} from '../src/canonical.mjs';
import {purchaseId} from '../src/service.mjs';
import {nodeServer} from '../src/server.mjs';
import {PROFILE_HASH} from '../src/profile.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {verifySourceCommitments} from '../scripts/netlify-production-target.mjs';

// Load the exact production entry function; substitute only its runtime dependencies.
const hooks=registerHooks({load(url,context,next){
  if(url===new URL('../src/runtime.mjs',import.meta.url).href)return {format:'module',shortCircuit:true,
    source:'export async function runtimeFromEnvironment(){return new Proxy({}, {get(_target,key){const service=globalThis.__repairService;const value=service[key];return typeof value==="function"?value.bind(service):value;}})}'};
  return next(url,context);
}});
const {default:entry}=await import('../netlify/functions/standing.mjs');hooks.deregister();
const python=process.env.WHP_TEST_PYTHON??'python3';
const artifacts=new URL('../public/buyer/',import.meta.url);
const cleanup=new Set();test.after(async()=>{for(const close of cleanup)await close();});

async function harness(options={}){
  const x=await setup(options);globalThis.__repairService=x.service;
  const requests=[];
  const handle=async req=>{
    const path=new URL(req.url).pathname;requests.push({method:req.method,path,proof:req.headers.has('whp-client-proof'),payment:req.headers.get('payment-signature')});
    if(['/buyer/manifest.json','/buyer/standing-buyer.tar.gz','/buyer/README.md'].includes(path))return new Response(await readFile(new URL(path.split('/').at(-1),artifacts)));
    return entry(req);
  };
  const server=nodeServer({get origin(){return x.service.origin;},handle});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));x.service.origin='http://127.0.0.1:'+server.address().port;
  const h={...x,requests,server,async close(){if(!cleanup.delete(close))return;await new Promise(r=>server.close(r));await this.store.close();}};
  const close=()=>h.close();cleanup.add(close);return h;
}
function policy(x){return {environment:'TEST',origin:x.service.origin,root_pin:x.f.rootPin,profile_hash:PROFILE_HASH,
  network:x.f.requirements.network,asset:x.f.requirements.asset,pay_to:x.f.requirements.payTo,payer:'0x'+'33'.repeat(20),
  asset_name:'USDC',asset_version:'2',max_per_purchase:'1000000',max_total:'2000000'};}
async function downloaded(x){
  const discovery=await (await fetch(x.service.origin+'/.well-known/whp-standing.json')).json();
  const contractResponse=await fetch(discovery.contract_url),contractBytes=await contractResponse.text(),contract=parseStrict(contractBytes,1048576);
  const resolutionBytes=await (await fetch(discovery.resolution_url)).text();
  assert.equal(parseStrict(resolutionBytes,1048576).payload.service_contract.sha256,hash(contract));
  const client=contract.purchase.buyer_client,archive=Buffer.from(await (await fetch(client.url)).arrayBuffer());
  assert.equal(hashBytes(archive),client.sha256);assert.equal(client.buyer_authentication_signature_required,false);
  const dir=await mkdtemp(join(tmpdir(),'whp-downloaded-buyer-'));
  const close=async()=>{cleanup.delete(close);await rm(dir,{recursive:true,force:true});};cleanup.add(close);
  await writeFile(join(dir,'buyer.tar.gz'),archive);execFileSync('tar',['-xzf',join(dir,'buyer.tar.gz'),'-C',dir]);
  for(const [file,digest] of Object.entries(client.source_files))assert.equal(hashBytes(await readFile(join(dir,file))),digest);
  assert.equal(hashBytes(await readFile(join(dir,'verify/verify_mark.py'))),VERIFIER_HASH);
  await writeFile(join(dir,'resolution.json'),resolutionBytes);await writeFile(join(dir,'contract.json'),canonical(contract.public_contract.document));
  const resolutionCheck=JSON.parse(execFileSync(python,[join(dir,'verify/verify_mark.py'),join(dir,'resolution.json'),'--resolution-only','--contract',join(dir,'contract.json'),'--root-pin',x.f.rootPin,'--allow-test','--at',String(NOW)],{encoding:'utf8'}));
  assert.equal(resolutionCheck.verified,true);
  const modules=await Promise.all(['src/buyer.mjs','src/buyer-journal.mjs','verify/python-verifier.mjs'].map(p=>import(pathToFileURL(join(dir,p)).href)));
  return {dir,contract,StandingBuyer:modules[0].StandingBuyer,BuyerJournal:modules[1].BuyerJournal,pythonVerifier:modules[2].pythonVerifier,
    close};
}
function buyer(x,pkg,{journal=new pkg.BuyerJournal(':memory:'),fetchImpl=fetch,changes={}}={}){
  let signatures=0;
  const paymentSigner={async signTypedData(payer,typed){signatures++;assert.equal(payer,policy(x).payer);assert.equal(typed.primaryType,'TransferWithAuthorization');return '0x'+'11'.repeat(64)+'1b';}};
  const agent=new pkg.StandingBuyer({policy:{...policy(x),...changes},paymentSigner,journal,fetchImpl,clock:()=>NOW,
    verifyResult:pkg.pythonVerifier({rootPin:x.f.rootPin,allowTest:true,python})});
  return {agent,journal,get signatures(){return signatures;}};
}

test('production entry catches async request faults before storage/payment and preserves internal 503',async()=>{
  const x=await harness();try{
    const calls=x.store.calls;
    for(const [body,type,status,code] of [['{','application/json',400,'INVALID_JSON'],['','application/json',400,'INVALID_JSON'],['{}','application/json',400,'FIELDS_INVALID'],['{}','text/plain',415,'CONTENT_TYPE_REQUIRED']]){
      const r=await fetch(x.service.origin+'/v1/evaluations',{method:'POST',headers:{'content-type':type},body});
      assert.equal(r.status,status);assert.equal((await r.json()).error.code,code);assert.equal(r.headers.has('payment-required'),false);
    }
    assert.equal(x.store.calls,calls);assert.equal(x.rail.verifyCalls,0);assert.equal(x.rail.settleCalls,0);
    const quote=x.store.quote;x.store.quote=async()=>{throw new Error('internal database detail');};
    const r=await fetch(x.service.origin+'/v1/evaluations',{method:'POST',headers:{'content-type':'application/json'},body:canonical(x.f.submission)});
    assert.equal(r.status,503);assert.equal((await r.json()).error.code,'SERVICE_UNAVAILABLE');x.store.quote=quote;
  }finally{await x.close();}
});

test('published discovery downloads runnable buyer; production entry returns independently verified TEST Mark and unchanged signed graph',async()=>{
  const x=await harness(),pkg=await downloaded(x),b=buyer(x,pkg);try{
    const r=await b.agent.purchase(x.f.submission),p=parseStrict(r.result_bytes,1048576);
    assert.equal(r.state,'VERIFIED');assert.equal(r.verification.evaluation_replay,'VERIFIED');assert.equal(r.verification.environment,'TEST');
    assert.equal(r.verification.current_standing,'ACTIVE');assert.equal(r.verification.live_completion_verified,false);
    assert.equal(p.protected.type,'WHP-STANDING-MARK-v1');assert.equal(canonical(p.payload.submission),canonical(x.f.submission));
    assert.equal(r.purchase_id,purchaseId(x.f.submission,x.f.rootPin));assert.equal(p.payload.protocol.sha256,CONTRACT_HASH);
    assert.equal((await b.agent.retrieve(x.f.submission)).result_bytes,r.result_bytes);
    assert.equal(b.signatures,1);assert.equal(x.rail.transfers,1);assert.equal(x.requests.some(r=>r.proof),false);
    assert.match(await (await fetch(x.service.origin+'/llms.txt')).text(),/buyer\/README.md/);
    const mcp=await (await fetch(x.service.origin+'/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'whp_standing_contract',arguments:{}}})})).json();
    assert.equal(mcp.result.structuredContent.purchase.buyer_client.sha256,pkg.contract.purchase.buyer_client.sha256);
  }finally{b.journal.close();await pkg.close();await x.close();}
});

test('production buyer preserves a negative assessment without manufacturing a Mark',async()=>{
  const x=await harness(),pkg=await downloaded(x),b=buyer(x,pkg);try{
    const s=clone(x.f.submission);s.requested_operation='EXECUTE';
    const r=await b.agent.purchase(s),p=parseStrict(r.result_bytes,1048576);
    assert.equal(r.state,'VERIFIED');assert.equal(p.protected.type,'WHP-STANDING-ASSESSMENT-v1');
    assert.equal(p.payload.mark_id,null);assert.equal(p.payload.standing,null);assert.equal(r.verification.current_standing,'ASSESSED_NO_MARK');
    assert.equal(canonical(p.payload.submission),canonical(s));assert.equal(b.signatures,1);assert.equal(x.rail.transfers,1);
  }finally{b.journal.close();await pkg.close();await x.close();}
});

test('pending settlement survives both durable stores reopening and recovers without another wallet signature or transfer',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'whp-recovery-')),rail=new FakeRail();rail.mode='timeout-after-transfer';rail.reveal=false;
  const x=await harness({filename:join(dir,'service.sqlite'),rail}),pkg=await downloaded(x),journalFile=join(dir,'buyer.sqlite');
  let b=buyer(x,pkg,{journal:new pkg.BuyerJournal(journalFile)});try{
    const pending=await b.agent.purchase(x.f.submission);assert.equal(pending.state,'PENDING');assert.equal(pending.additional_charge,false);assert.equal(b.signatures,1);assert.equal(rail.transfers,1);
    const stored=b.journal.get(pending.purchase_id);b.journal.close();await x.store.close();
    const restarted=await setup({filename:join(dir,'service.sqlite'),f:x.f,rail});restarted.service.origin=x.service.origin;
    x.service=restarted.service;x.store=restarted.store;globalThis.__repairService=x.service;rail.reveal=true;
    b=buyer(x,pkg,{journal:new pkg.BuyerJournal(journalFile)});
    const r=await b.agent.purchase(x.f.submission);assert.equal(r.state,'VERIFIED');assert.equal(r.purchase_id,pending.purchase_id);
    assert.deepEqual(b.journal.get(r.purchase_id).payment,stored.payment);assert.equal(b.signatures,0);assert.equal(rail.transfers,1);assert.equal(rail.settleCalls,1);
    assert.ok(x.requests.some(r=>r.path.endsWith('/recover')));assert.equal(x.requests.some(r=>r.proof),false);
  }finally{b.journal.close();await pkg.close();await x.close();await rm(dir,{recursive:true,force:true});}
});

test('lost paid response and lost pre-send request replay the same purchase and authorization',async()=>{
  for(const dropBefore of [false,true]){
    const x=await harness(),pkg=await downloaded(x),journalFile=join(pkg.dir,'buyer.sqlite');let drop=true;
    let b=buyer(x,pkg,{journal:new pkg.BuyerJournal(journalFile),fetchImpl:async(url,opts)=>{
      if(drop&&opts.headers['payment-signature']){drop=false;if(!dropBefore)await fetch(url,opts);throw new Error('Lost paid request/response');}return fetch(url,opts);
    }});
    try{
      await assert.rejects(()=>b.agent.purchase(x.f.submission),/Lost paid/);assert.equal(b.signatures,1);
      const row=b.journal.get(purchaseId(x.f.submission,x.f.rootPin));b.journal.close();
      b=buyer(x,pkg,{journal:new pkg.BuyerJournal(journalFile)});const r=await b.agent.purchase(x.f.submission);
      assert.equal(r.state,'VERIFIED');assert.equal(b.signatures,0);assert.equal(x.rail.transfers,1);
      for(const req of x.requests.filter(r=>r.payment))assert.equal(canonical(decode(req.payment)),canonical(row.payment));
    }finally{b.journal.close();await pkg.close();await x.close();}
  }
});

test('temporary failure after durable authorization is pending and recovery never signs again',async()=>{
  const x=await harness(),pkg=await downloaded(x);let down=true;
  const b=buyer(x,pkg,{fetchImpl:(url,opts)=>down&&opts.headers['payment-signature']?Promise.resolve(new Response('{}',{status:503})):fetch(url,opts)});
  try{const p=await b.agent.purchase(x.f.submission);assert.equal(p.state,'PENDING');assert.equal(p.http_status,503);assert.equal(p.additional_charge,false);
    down=false;assert.equal((await b.agent.purchase(x.f.submission)).state,'VERIFIED');assert.equal(b.signatures,1);assert.equal(x.rail.transfers,1);
  }finally{b.journal.close();await pkg.close();await x.close();}
});

test('public path retains budget, exact quote/nonce binding and immutable submission identity',async()=>{
  const x=await harness(),pkg=await downloaded(x);
  const low=buyer(x,pkg,{changes:{max_per_purchase:'999999'}});try{
    await assert.rejects(()=>low.agent.purchase(x.f.submission),/BUYER_PER_PURCHASE_LIMIT/);assert.equal(low.signatures,0);
  }finally{low.journal.close();}
  const b=buyer(x,pkg,{changes:{max_total:'1000000'}});try{
    let corrupt=true;const ordinary=b.agent.fetch;
    b.agent.fetch=async(url,opts)=>{if(corrupt&&opts.headers['payment-signature']){const p=decode(opts.headers['payment-signature']);p.payload.authorization.nonce='0x'+'00'.repeat(32);opts={...opts,headers:{...opts.headers,'payment-signature':Buffer.from(canonical(p)).toString('base64')}};}return ordinary(url,opts);};
    await assert.rejects(()=>b.agent.purchase(x.f.submission),/BUYER_EVALUATION_REFUSED/);assert.equal(x.rail.verifyCalls,0);assert.equal(x.rail.transfers,0);
    corrupt=false;const r=await b.agent.purchase(x.f.submission);assert.equal(r.state,'VERIFIED');assert.equal(b.signatures,1);
    const changed=clone(x.f.submission);changed.requested_operation='RECOMMEND';
    await assert.rejects(()=>b.agent.purchase(changed),/BUYER_IDEMPOTENCY_CONFLICT/);
    const conflict=await fetch(x.service.origin+'/v1/evaluations',{method:'POST',headers:{'content-type':'application/json'},body:canonical(changed)});assert.equal(conflict.status,409);
    const second=clone(x.f.submission);second.client_reference+='-second';await assert.rejects(()=>b.agent.purchase(second),/BUYER_TOTAL_SPENDING_LIMIT/);
    assert.equal(b.signatures,1);assert.equal(x.rail.transfers,1);
  }finally{b.journal.close();await pkg.close();await x.close();}
});

test('frozen contract, profile and standalone verifier commitments remain unchanged',async()=>{
  const c=await verifySourceCommitments();assert.equal(c.contract,CONTRACT_HASH);assert.equal(c.verifier,VERIFIER_HASH);assert.equal(c.profile,PROFILE_HASH);
});
