import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {fixture,setup,NOW} from './fixtures.mjs';
import {BuyerJournal} from '../src/buyer-journal.mjs';
import {StandingBuyer,Eip1193Signer} from '../src/buyer.mjs';
import {pythonVerifier} from '../verify/python-verifier.mjs';
import {nodeServer} from '../src/server.mjs';
import {PROFILE_HASH} from '../src/profile.mjs';
import {clone,hash} from '../src/canonical.mjs';
function policy(x){return {environment:'TEST',origin:x.service.origin,root_pin:x.f.rootPin,profile_hash:PROFILE_HASH,network:x.f.requirements.network,asset:x.f.requirements.asset,
  pay_to:x.f.requirements.payTo,payer:'0x'+'33'.repeat(20),asset_name:'USDC',asset_version:'2',max_per_purchase:'1000000',max_total:'2000000'};}
function buyer(x,{journal=new BuyerJournal(':memory:'),changes={},fetchImpl=(url,options)=>x.service.handle(new Request(url,options))}={}){
  let signatures=0;
  const provider={request:async({method,params})=>{assert.equal(method,'eth_signTypedData_v4');const t=JSON.parse(params[1]);assert.equal(t.primaryType,'TransferWithAuthorization');assert.equal(t.domain.chainId,'8453');assert.equal(t.message.to,x.f.requirements.payTo);signatures++;return '0x'+'11'.repeat(64)+'1b';}};
  const agent=new StandingBuyer({policy:{...policy(x),...changes},privateKey:x.f.buyer.privateKey,paymentSigner:new Eip1193Signer(provider),journal,
    verifyResult:pythonVerifier({rootPin:x.f.rootPin,allowTest:true}),fetchImpl,clock:()=>NOW});
  return {agent,journal,get signatures(){return signatures;}};
}

test('autonomous buyer discovers, enforces allowance, signs bound authorization, pays, independently verifies and retrieves without signing again',async()=>{
  const x=await setup(),b=buyer(x);try{const first=await b.agent.purchase(x.f.submission);assert.equal(first.state,'VERIFIED');assert.equal(first.verification.current_standing,'ACTIVE');assert.equal(first.verification.environment,'TEST');assert.equal(first.verification.live_completion_verified,false);
    const second=await b.agent.retrieve(x.f.submission);assert.equal(second.result_bytes,first.result_bytes);assert.equal(b.signatures,1);assert.equal(x.rail.transfers,1);assert.equal(x.rail.settleCalls,1);
  }finally{b.journal.close();await x.store.close();}
});
for(const [name,changes,code] of [['per-purchase maximum',{max_per_purchase:'999999'},'BUYER_PER_PURCHASE_LIMIT'],['recipient pin',{pay_to:'0x'+'44'.repeat(20)},'BUYER_PAYMENT_DESTINATION_NOT_AUTHORIZED'],['root pin',{root_pin:'00'.repeat(32)},'UNTRUSTED_ROOT'],['token domain',{asset_name:'NotUSDC'},'BUYER_EIP712_DOMAIN_NOT_AUTHORIZED']]){
  test('buyer rejects '+name+' before invoking wallet signer',async()=>{const x=await setup(),b=buyer(x,{changes});try{await assert.rejects(()=>b.agent.purchase(x.f.submission),new RegExp(code));assert.equal(b.signatures,0);assert.equal(x.rail.verifyCalls,0);assert.equal(x.rail.transfers,0);}finally{b.journal.close();await x.store.close();}});
}
test('durable aggregate allowance prevents a second distinct purchase exceeding the cap',async()=>{const x=await setup(),b=buyer(x,{changes:{max_total:'1000000'}});try{await b.agent.purchase(x.f.submission);const second=clone(x.f.submission);second.client_reference+='b';await assert.rejects(()=>b.agent.purchase(second),/BUYER_TOTAL_SPENDING_LIMIT/);assert.equal(b.signatures,1);assert.equal(x.rail.transfers,1);}finally{b.journal.close();await x.store.close();}});
test('buyer journal rejects a changed submitted object under the same reference',async()=>{const x=await setup(),b=buyer(x);try{await b.agent.purchase(x.f.submission);const changed=clone(x.f.submission);changed.requested_operation='RECOMMEND';await assert.rejects(()=>b.agent.purchase(changed),/BUYER_IDEMPOTENCY_CONFLICT/);assert.equal(b.signatures,1);}finally{b.journal.close();await x.store.close();}});
test('buyer process state survives journal reopen and a lost paid HTTP response without another wallet signature',async()=>{
  const x=await setup(),dir=mkdtempSync(join(tmpdir(),'whp-buyer-'));let drop=true;
  const journalPath=join(dir,'journal.sqlite');const first=buyer(x,{journal:new BuyerJournal(journalPath),fetchImpl:async(url,options)=>{const r=await x.service.handle(new Request(url,options));if(drop&&r.status===200&&options.headers['payment-signature']){drop=false;throw new Error('Lost paid HTTP response');}return r;}});
  try{await assert.rejects(()=>first.agent.purchase(x.f.submission),/Lost paid HTTP/);assert.equal(first.signatures,1);first.journal.close();const second=buyer(x,{journal:new BuyerJournal(journalPath)});try{const r=await second.agent.purchase(x.f.submission);assert.equal(r.state,'VERIFIED');assert.equal(second.signatures,0);assert.equal(x.rail.transfers,1);}finally{second.journal.close();}}
  finally{await x.store.close();rmSync(dir,{recursive:true,force:true});}
});
test('real localhost HTTP service completes the autonomous test transaction',async()=>{
  const x=await setup();const server=nodeServer(x.service);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));x.service.origin='http://127.0.0.1:'+server.address().port;const b=buyer(x,{fetchImpl:fetch});
  try{const r=await b.agent.purchase(x.f.submission);assert.equal(r.state,'VERIFIED');assert.equal(x.rail.transfers,1);const r2=await b.agent.retrieve(x.f.submission);assert.equal(hash(r2.result_bytes),hash(r.result_bytes));}
  finally{b.journal.close();await new Promise(resolve=>server.close(resolve));await x.store.close();}
});
test('buyer remembers the highest verified trust epoch and refuses rollback',async()=>{const x=await setup(),b=buyer(x);try{
  const first=x.f.trustBundle.status_snapshot;b.journal.rememberTrust(x.f.rootPin,first);
  const updated=clone(first);updated.payload.sequence=1;b.journal.rememberTrust(x.f.rootPin,updated);
  assert.throws(()=>b.journal.rememberTrust(x.f.rootPin,first),/BUYER_TRUST_ROLLBACK/);
}finally{b.journal.close();await x.store.close();}});
