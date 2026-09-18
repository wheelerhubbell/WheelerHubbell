// New direct-wallet connections only. Real EIP-712 signatures, TEST settlement only.
// No StandingBuyer import/download on the client side, no live key, chain or funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {registerHooks,createRequire} from 'node:module';
import {mkdtemp,rm,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setup,fixture,refreshTrustStatus,NOW,FakeRail} from './fixtures.mjs';
import {nodeServer} from '../src/server.mjs';
import {Fault,canonical,parseStrict,hash} from '../src/canonical.mjs';
import {pythonVerifier} from '../verify/python-verifier.mjs';

// Reuse an existing ordinary wallet library; it is not a production dependency.
const walletRequire=createRequire(process.env.WHP_TEST_WALLET_PACKAGE??import.meta.url);
const {privateKeyToAccount}=walletRequire('viem/accounts');
const {verifyTypedData}=walletRequire('viem');
const walletVersion=walletRequire('viem/package.json').version;
const account=privateKeyToAccount('0x'+'01'.repeat(32)); // disposable TEST signing key
const transferTypes={TransferWithAuthorization:[{name:'from',type:'address'},{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'validAfter',type:'uint256'},{name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}]};
class SignatureCheckingTestRail extends FakeRail {
  async verify(payment,requirements){
    const valid=await verifyTypedData({address:payment.payload.authorization.from,
      domain:{name:requirements.extra.name,version:requirements.extra.version,chainId:Number(requirements.network.slice(7)),verifyingContract:requirements.asset},
      types:transferTypes,primaryType:'TransferWithAuthorization',message:payment.payload.authorization,signature:payment.payload.signature});
    if(!valid)throw new Fault('PAYMENT_SIGNATURE_OR_STATE_INVALID',402);
    return super.verify(payment,requirements);
  }
}
const hooks=registerHooks({load(url,context,next){
  if(url===new URL('../src/runtime.mjs',import.meta.url).href)return {format:'module',shortCircuit:true,
    source:'export async function runtimeFromEnvironment(){return new Proxy({}, {get(_target,key){const service=globalThis.__directWalletService;const value=service[key];return typeof value==="function"?value.bind(service):value;}})}'};
  return next(url,context);
}});
const {default:entry}=await import('../netlify/functions/standing.mjs');hooks.deregister();
const cleanup=new Set();test.after(async()=>{for(const close of cleanup)await close();});
async function harness(options={}){
  const x=await setup({rail:new SignatureCheckingTestRail(),...options}),requests=[];
  globalThis.__directWalletService=x.service;
  const server=nodeServer({get origin(){return x.service.origin;},async handle(req){requests.push({method:req.method,path:new URL(req.url).pathname,proof:req.headers.has('whp-client-proof')});return entry(req);}});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));x.service.origin='http://127.0.0.1:'+server.address().port;
  const h={...x,server,requests,async close(){if(!cleanup.delete(close))return;await new Promise(r=>server.close(r));await this.store.close();}};
  const close=()=>h.close();cleanup.add(close);return h;
}
async function discovery(x){
  const d=await (await fetch(x.service.origin+'/.well-known/whp-standing.json')).json();
  const c=await (await fetch(d.contract_url)).json();
  assert.equal(c.purchase.direct_wallet.buyer_installation_required,false);return c;
}
function ownerWallet(x,{limit=1000000n}={}){
  let calls=0,spent=0n;const signed=new Map();
  return {get calls(){return calls;},async request({method,params}){
    // Existing owner policy remains on the BUYER side, outside merchant control.
    assert.equal(method,'eth_signTypedData_v4');assert.equal(params[0],account.address.toLowerCase());
    const data=JSON.parse(params[1]);assert.equal(data.primaryType,'TransferWithAuthorization');
    assert.equal(data.domain.verifyingContract,x.f.requirements.asset);assert.equal(String(data.domain.chainId),x.f.requirements.network.slice(7));
    assert.equal(data.domain.name,x.f.requirements.extra.name);assert.equal(data.domain.version,x.f.requirements.extra.version);
    assert.equal(data.message.from,account.address.toLowerCase());assert.equal(data.message.to,x.f.requirements.payTo);
    assert.ok(BigInt(data.message.validBefore)-BigInt(data.message.validAfter)<=301n);
    if(signed.has(data.message.nonce))return signed.get(data.message.nonce);
    const value=BigInt(data.message.value);assert.ok(value<=1000000n&&spent+value<=limit,'OWNER_SPENDING_LIMIT');spent+=value;calls++;
    const signature=await account.signTypedData(data);signed.set(data.message.nonce,signature);return signature;
  }};
}
const post=(url,body,headers={})=>fetch(url,{method:'POST',headers:{'content-type':'application/json',...headers},body});
async function rpc(x,method,params={}){
  const r=await fetch(x.service.origin+'/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
  assert.equal(r.status,200);return r.json();
}
async function tool(x,name,args){const r=await rpc(x,'tools/call',{name,arguments:args});assert.ok(r.result,JSON.stringify(r));return r.result.structuredContent;}
async function independentlyVerify(x,bytes,at=NOW){
  const result=JSON.parse(bytes),registry=await (await fetch(x.service.origin+'/v1/registry/'+result.payload.purchase_id)).text();
  const report=await pythonVerifier({rootPin:x.f.rootPin,allowTest:true})(bytes,registry,at);
  assert.equal(report.verified,true);assert.equal(report.environment,'TEST');assert.equal(report.live_completion_verified,false);return report;
}

test('existing viem wallet signs published instructions; exactly two HTTP acquisition requests and independent verification, no buyer install',async t=>{
  t.diagnostic('Generic wallet library: viem '+walletVersion+'; real local EIP-712 signature; no chain or funds');
  const x=await harness();try{
    const c=await discovery(x),direct=c.purchase.direct_wallet,raw=JSON.stringify(x.f.submission),wallet=ownerWallet(x);
    const unpaid=await post(c.purchase.url,raw,{[direct.payer_header]:account.address});assert.equal(unpaid.status,402);
    const terms=await unpaid.json(),info=terms.extensions['whp-standing'].info,checkout=info.wallet_checkout;
    assert.equal(checkout.eligibility.can_produce_mark,true);
    const header=JSON.parse(Buffer.from(unpaid.headers.get('payment-required'),'base64').toString());
    assert.equal(canonical(header.accepts),canonical(terms.accepts));assert.equal(canonical(header.extensions['whp-standing'].info.quote),canonical(info.quote));
    assert.equal(checkout.buyer_authentication_signature_required,false);
    const signature=await wallet.request(checkout.wallet_request);
    const paid=await post(checkout.submit.url,raw,{[checkout.submit.payer_header]:checkout.submit.payer,[checkout.submit.signature_header]:signature});assert.equal(paid.status,200);
    const bytes=await paid.text(),p=JSON.parse(bytes).payload;
    assert.equal(p.mark_id!==null,true);assert.equal(canonical(p.submission),canonical(x.f.submission));
    assert.equal(p.commerce.payment_payload.payload.signature,signature);
    assert.equal(canonical(p.commerce.payment_payload.payload.authorization),canonical(JSON.parse(checkout.wallet_request.params[1]).message));
    assert.equal((await independentlyVerify(x,bytes)).current_standing,'ACTIVE');
    const retrieved=await (await fetch(checkout.recovery.result_url)).text();assert.equal(retrieved,bytes);
    assert.equal(wallet.calls,1);assert.equal(x.rail.transfers,1);assert.equal(x.requests.filter(r=>r.path==='/v1/evaluations').length,2);
    assert.equal(x.requests.some(r=>r.proof||r.path.startsWith('/buyer/')),false);
    const spec=await (await fetch(x.service.origin+'/v1/openapi.json')).json();assert.ok(spec.paths['/v1/evaluations'].post.parameters.some(p=>p.name===direct.signature_header));
  }finally{await x.close();}
});

test('MCP exposes direct wallet and recover; pending and lost-response recovery reuse durable identity after restart and expiry',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'whp-direct-recovery-')),filename=join(dir,'service.sqlite');
  let at=NOW;const rail=new SignatureCheckingTestRail();rail.reveal=false;rail.mode='timeout-after-transfer';
  const x=await harness({filename,rail,clock:()=>at});try{
    const tools=(await rpc(x,'tools/list')).result.tools;
    assert.ok(tools.some(t=>t.name==='whp_standing_recover'));assert.ok(tools.find(t=>t.name==='whp_standing_evaluation').inputSchema.properties.wallet_signature);
    const c=(await rpc(x,'tools/call',{name:'whp_standing_contract',arguments:{}})).result.structuredContent;
    const direct=c.purchase.direct_wallet,raw=JSON.stringify(x.f.submission),wallet=ownerWallet(x);
    const unpaid=await tool(x,direct.mcp.tool,{submission_raw:raw,payer:account.address});assert.equal(unpaid.http_status,402);
    const checkout=JSON.parse(unpaid.body_bytes).extensions['whp-standing'].info.wallet_checkout;
    const signature=await wallet.request(checkout.wallet_request),args={submission_raw:raw,payer:account.address,wallet_signature:signature};
    // The host's ordinary durable job state, not an installed WHP BuyerJournal.
    const stateFile=join(dir,'agent-job.json');await writeFile(stateFile,JSON.stringify({purchase_id:checkout.purchase_id,args}));
    const pending=await tool(x,direct.mcp.tool,args);assert.equal(pending.http_status,202);assert.equal(JSON.parse(pending.body_bytes).additional_charge,false);
    await x.store.close();at=NOW+800;
    const restart=await setup({filename,f:x.f,rail,clock:()=>at});restart.service.origin=x.service.origin;x.service=restart.service;x.store=restart.store;globalThis.__directWalletService=x.service;
    const saved=JSON.parse(await readFile(stateFile,'utf8'));
    assert.equal((await tool(x,checkout.recovery.mcp_result_tool,{purchase_id:saved.purchase_id})).http_status,202);
    rail.reveal=true;
    const recovered=await tool(x,checkout.recovery.mcp_recover_tool,{purchase_id:saved.purchase_id});assert.equal(recovered.http_status,200);
    assert.equal((await independentlyVerify(x,recovered.body_bytes,at)).verified,true);
    // Repeating the original signed request after an uncertain/lost result is retrieval.
    const replay=await tool(x,direct.mcp.tool,saved.args);assert.equal(replay.body_bytes,recovered.body_bytes);
    assert.equal(wallet.calls,1);assert.equal(rail.settleCalls,1);assert.equal(rail.transfers,1);assert.equal(x.requests.some(r=>r.proof),false);
  }finally{await x.close();await rm(dir,{recursive:true,force:true});}
});

test('unadmitted source is identified in unpaid checkout; paid negative assessment remains negative',async()=>{
  const f=fixture();f.trustBundle.certificates=f.trustBundle.certificates.filter(c=>!c.payload.roles.includes('SOURCE'));refreshTrustStatus(f);
  const x=await harness({f});try{
    const raw=JSON.stringify(f.submission),c=await discovery(x),direct=c.purchase.direct_wallet,wallet=ownerWallet(x);
    const unpaid=await post(c.purchase.url,raw,{[direct.payer_header]:account.address}),terms=await unpaid.json();assert.equal(unpaid.status,402);
    const checkout=terms.extensions['whp-standing'].info.wallet_checkout;
    assert.equal(checkout.eligibility.can_produce_mark,false);assert.ok(checkout.eligibility.failed_checks.some(c=>c.rule==='SOURCE_AUTHORITY'));
    assert.equal(wallet.calls,0);assert.equal(x.rail.transfers,0);
    // Explicit TEST purchase of the negative assessment, not a request to invent standing.
    const signature=await wallet.request(checkout.wallet_request);
    const paid=await post(checkout.submit.url,raw,{[direct.payer_header]:account.address,[direct.signature_header]:signature});assert.equal(paid.status,200);
    const bytes=await paid.text(),result=JSON.parse(bytes);assert.equal(result.protected.type,'WHP-STANDING-ASSESSMENT-v1');assert.equal(result.payload.mark_id,null);assert.equal(result.payload.standing,null);
    assert.equal((await independentlyVerify(x,bytes)).current_standing,'ASSESSED_NO_MARK');
  }finally{await x.close();}
});

test('server preparation cannot bypass wallet policy, alter exact binding or create fresh authorization on retry',async()=>{
  let at=NOW;const x=await harness({clock:()=>at});try{
    const c=await discovery(x),d=c.purchase.direct_wallet,raw=JSON.stringify(x.f.submission);
    const getQuote=async()=>{const r=await post(c.purchase.url,raw,{[d.payer_header]:account.address});return {status:r.status,body:await r.json()};};
    const first=await getQuote(),checkout=first.body.extensions['whp-standing'].info.wallet_checkout;
    const refusedWallet=ownerWallet(x,{limit:0n});await assert.rejects(()=>refusedWallet.request(checkout.wallet_request),/OWNER_SPENDING_LIMIT/);assert.equal(refusedWallet.calls,0);
    at+=15;const repeat=await getQuote();assert.equal(canonical(repeat.body.extensions['whp-standing'].info.wallet_checkout.wallet_request),canonical(checkout.wallet_request));
    const altered=JSON.parse(checkout.wallet_request.params[1]);altered.message.nonce='0x'+'99'.repeat(32);
    const wrongSignature=await account.signTypedData(altered);
    let r=await post(c.purchase.url,raw,{[d.payer_header]:account.address,[d.signature_header]:wrongSignature});assert.equal(r.status,402);assert.equal((await r.json()).error.code,'PAYMENT_SIGNATURE_OR_STATE_INVALID');
    r=await post(c.purchase.url,raw,{[d.payer_header]:account.address,[d.signature_header]:wrongSignature,'payment-signature':'ambiguous'});assert.equal(r.status,400);assert.equal((await r.json()).error.code,'MULTIPLE_PAYMENT_FORMATS');
    const changed={...x.f.submission,requested_operation:'RECOMMEND'};r=await post(c.purchase.url,JSON.stringify(changed),{[d.payer_header]:account.address});assert.equal(r.status,409);
    at=NOW+301;r=await post(c.purchase.url,raw,{[d.payer_header]:account.address});assert.equal(r.status,409);assert.equal((await r.json()).error.code,'WALLET_AUTHORIZATION_EXPIRED');
    assert.equal(x.rail.transfers,0);assert.equal(x.rail.settleCalls,0);
    const row=await x.store.get(checkout.purchase_id);assert.equal(hash(row.quote),hash(first.body.extensions['whp-standing'].info.quote));
  }finally{await x.close();}
});
