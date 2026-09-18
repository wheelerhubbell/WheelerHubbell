import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {readFile,writeFile,mkdir,mkdtemp,copyFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {x402Client} from '@x402/core/client';
import {ExactEvmScheme} from '@x402/evm/exact/client';
import {privateKeyToAccount} from 'viem/accounts';
import {verifyTypedData} from 'viem';
import {fixture,setup,refreshTrustStatus,FakeRail} from './fixtures.mjs';
import {hash,canonical,seal,publicDer,randomHex,Fault,encode} from '../src/canonical.mjs';
import {publicMachineRoute} from '../src/public-machine.mjs';
import {nodeServer} from '../src/server.mjs';
import {MANIFEST_PATH,observeNamespaces} from '../src/namespace-authority.mjs';
import {PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from '../src/profile.mjs';
import {STANDING_CAPABILITY} from '../src/need.mjs';
import {pythonVerifier} from '../verify/python-verifier.mjs';
import {StandingBuyer} from '../src/buyer.mjs';
import {BuyerJournal} from '../src/buyer-journal.mjs';
import {fixture as legacyFixture} from './helpers/legacy-fixture.mjs';
import {evaluate as legacyEvaluate} from '../legacy/v1/src/evaluator.mjs';
import {validatePayment as legacyValidatePayment,authorizationNonce} from '../src/payment.mjs';

const python=process.env.WHP_TEST_PYTHON??'python3';
const now=()=>Math.floor(Date.now()/1000);
const type={TransferWithAuthorization:[{name:'from',type:'address'},{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'validAfter',type:'uint256'},{name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}]};
class SignedTestRail extends FakeRail{
  async verify(p,r){const ok=await verifyTypedData({address:p.payload.authorization.from,domain:{name:r.extra.name,version:r.extra.version,chainId:Number(r.network.slice(7)),verifyingContract:r.asset},types:type,primaryType:'TransferWithAuthorization',message:p.payload.authorization,signature:p.payload.signature});if(!ok)throw new Fault('PAYMENT_SIGNATURE_INVALID',402);return super.verify(p,r);}
}
const listen=async server=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+server.address().port;};
function ownObject(name,requirements,at=now()){
  const source=generateKeyPairSync('ed25519'),transition=generateKeyPairSync('ed25519'),namespace='https://github.com/independent-'+name+'/records';
  const bounds={scope:namespace,jurisdiction:'namespace-control',valid_from:at-10,valid_until:at+1200};
  const leaf={id:name+'-observation',version:'1',content:{report:name+' owns an unrelated bounded object',count:name==='a'?3:17},locator:namespace+'/blob/main/observation.json',epistemic_status:'REPORT',qualifiers:['Repository-controller attestation only.','No external-world truth claim.'],unknowns:[{id:'external',description:'External validity unassessed.',blocks:['EXECUTE']}],operations:['INFORM'],...bounds,status:'ACTIVE',prior_hash:null};
  const target={...structuredClone(leaf),id:name+'-copy',locator:namespace+'/blob/main/copy.json'};
  const edge={from:[hash(leaf)],to:hash(target),transform:'COPY',operations:['INFORM'],...bounds,warrant:{statement:'Exact copy of this repository record, with all bounds and unknowns.',evidence_hashes:[hash(leaf)]}};
  const manifest={version:'WHP-NAMESPACE-GRANTS-v1',namespace,valid_from:at-30,valid_until:at+1500,grants:[
    {public_key:publicDer(source.privateKey),role:'SOURCE',payload_hashes:[hash(leaf),hash(target)],...bounds,operations:['INFORM']},
    {public_key:publicDer(transition.privateKey),role:'TRANSITION',payload_hashes:[hash(edge)],...bounds,operations:['INFORM']}
  ]};
  const object={id:target.id,version:target.version,root:hash(target)},nodes=[leaf,target].map(p=>seal('WHP-SOURCE-ATTESTATION-v1',p,source.privateKey)),transitions=[seal('WHP-TRANSITION-WARRANT-v1',edge,transition.privateKey)];
  const authority=[{namespace,manifest_sha256:hash(manifest)}];
  const task={required:true,capability_class:STANDING_CAPABILITY.id,properties:STANDING_CAPABILITY.requirements,operation:'INFORM'};
  const input={object,bounds,nodes,transitions,authority,task,wallet:{test_key:'0x'+(name==='a'?'01':'02').repeat(32),policy:{chain_id:requirements.network.slice(7),asset:requirements.asset,pay_to:requirements.payTo,max_amount:requirements.amount}}};
  const submission={version:'WHP-STANDING-SUBMISSION-v1.1',client_reference:randomHex(32),profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH},object,bounds,nodes,transitions,authority,requested_operation:'INFORM'};
  return {source,transition,manifest,input,submission};
}
function content(manifest){const raw=JSON.stringify(manifest);return {type:'file',path:MANIFEST_PATH,encoding:'base64',content:Buffer.from(raw).toString('base64'),sha:createHash('sha1').update('blob '+Buffer.byteLength(raw)+'\0'+raw).digest('hex')};}
async function harness(options={}){
  const f=fixture({at:now()});f.trustBundle.certificates=[seal('WHP-AUTHORITY-CERTIFICATE-v1',{...f.trustBundle.certificates[0].payload,scopes:['github-repository:*'],jurisdictions:['namespace-control']},f.root.privateKey)];refreshTrustStatus(f);
  const x=await setup({f,rail:new SignedTestRail(),clock:now,...options}),records=new Map(),requests=[],observations=[];
  const repository=createServer((req,res)=>{const key=req.url.slice(1),m=records.get(key);res.writeHead(m?200:404,{'content-type':'application/json'});res.end(JSON.stringify(m?content(m):{message:'Not Found'}));});
  const repoOrigin=await listen(repository);
  x.service.namespaceFetch=async(url,opts)=>{assert.match(url,/^https:\/\/api\.github\.com\/repos\/[a-z0-9-]+\/[a-z0-9_.-]+\/contents\/\.well-known\/standing-authority\.json$/);assert.equal(opts.redirect,'error');observations.push(url);const namespace=url.replace('https://api.github.com/repos/','https://github.com/').split('/contents/')[0];return fetch(repoOrigin+'/'+encodeURIComponent(namespace),opts);};
  const server=nodeServer({get origin(){return x.service.origin;},async handle(req){requests.push({path:new URL(req.url).pathname,method:req.method,buyer_proof:req.headers.has('whp-client-proof')});return await publicMachineRoute(x.service,req)??await x.service.handle(req);}});
  x.service.origin=await listen(server);
  const a=ownObject('a',f.requirements),b=ownObject('b',f.requirements);for(const o of [a,b])records.set(encodeURIComponent(o.manifest.namespace),o.manifest);
  return {...x,a,b,records,requests,observations,async close(){await Promise.all([server,repository].map(s=>new Promise(r=>s.close(r))));await this.store.close();}};
}
async function cold(input,{directory=null}={}){
  const dir=directory??await mkdtemp(join(tmpdir(),'cold-capability-buyer-'));
  try{
    await copyFile(new URL('../scripts/cold-purchaser.mjs',import.meta.url),join(dir,'consumer.mjs'));
    await writeFile(join(dir,'input.json'),JSON.stringify(input));
    const modules=resolve('node_modules');try{await symlink(modules,join(dir,'node_modules'));}catch(e){if(e.code!=='EEXIST')throw e;}
    const report=await new Promise((resolve,reject)=>{
      const args=['--permission','--allow-fs-read='+dir,'--allow-fs-write='+dir,'--allow-fs-read='+modules,'--allow-child-process',join(dir,'consumer.mjs'),join(dir,'input.json')];
      const p=spawn(process.execPath,args,{cwd:dir,env:{PATH:process.env.PATH,GENERIC_PYTHON:python,GENERIC_SANDBOX:resolvePath('scripts/public-artifact-sandbox.py')},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
      const timer=setTimeout(()=>{p.kill('SIGKILL');reject(Error('COLD_TIMEOUT'));},90000);
      p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('error',reject);p.on('close',code=>{clearTimeout(timer);try{resolve({code,report:JSON.parse(stdout),stderr});}catch{reject(Error(stdout+stderr));}});
    });
    let mark=null;try{mark=await readFile(join(dir,'mark.json'),'utf8');}catch{}
    return {...report,mark};
  }finally{if(!directory)await rm(dir,{recursive:true,force:true});}
}
const resolvePath=resolve;
const post=(x,s,p)=>fetch(x.service.origin+'/v1/evaluations',{method:'POST',headers:{'content-type':'application/json',...(p?{'payment-signature':encode(p)}:{})},body:JSON.stringify(s)});
async function signTerms(terms,key='03'){
  const account=privateKeyToAccount('0x'+key.repeat(32)),client=new x402Client().setSpendControls({allowedAssets:[{network:terms.accepts[0].network,asset:terms.accepts[0].asset,maxAmountPerPayment:terms.accepts[0].amount}]}).register('eip155:8453',new ExactEvmScheme(account));return client.createPaymentPayload(terms);
}

test('release gate: two clean standard-x402 buyers cross A → Mark A → independent task B → service → Mark B',{timeout:180000},async()=>{
  const x=await harness();let catalog;
  try{
    const consumer=await readFile('scripts/cold-purchaser.mjs','utf8');assert.doesNotMatch(consumer,/WHP|Wheeler|Hubbell|StandingBuyer|\/v1\/|fixture|src\//);
    catalog=createServer((req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({interface:'capability-catalog-v1',providers:[{capability_class:'unrelated',properties:[],resolution_url:'https://invalid.example'},{capability_class:STANDING_CAPABILITY.id,properties:STANDING_CAPABILITY.requirements,resolution_url:x.service.resolutionUrl}]}));});
    const directory=await listen(catalog);
    const a=await cold({...x.a.input,catalog_url:directory+'/capabilities'});assert.equal(a.code,0,JSON.stringify(a));assert.equal(a.report.wallet_calls,1);assert.ok(a.mark);
    const interaction={jsonrpc:'2.0',id:1,result:{content:[{type:'text',text:'Ordinary machine result with preserved provenance metadata.'}],_meta:{signed_artifacts:[Buffer.from(a.mark).toString('base64')]}}};
    const inputB={...x.b.input,interaction};assert.equal(inputB.catalog_url,undefined);assert.ok(!JSON.stringify(inputB).includes(x.service.origin));
    const b=await cold(inputB);assert.equal(b.code,0,JSON.stringify(b));assert.equal(b.report.wallet_calls,1);assert.equal(b.report.encountered.purchase_id,a.report.purchase_id);assert.notEqual(a.report.purchase_id,b.report.purchase_id);assert.notEqual(a.report.object_id,b.report.object_id);
    assert.notEqual(a.report.source_keys[0],b.report.source_keys[0]);assert.equal(x.f.trustBundle.certificates.length,1);assert.equal(x.rail.transfers,2);
    assert.equal(x.requests.some(r=>r.buyer_proof||r.path.startsWith('/buyer/')),false);
    for(const report of [a.report,b.report])assert.deepEqual(report.trace.filter(t=>t.method==='POST').map(t=>t.status),[402,200]);
    // Encounter alone must never cause a purchase; B's independent task controls relevance.
    const irrelevant=await cold({...inputB,task:{...inputB.task,required:false}});assert.equal(irrelevant.code,0,JSON.stringify(irrelevant));assert.equal(irrelevant.report.wallet_calls,0);assert.equal(irrelevant.report.trace.length,0);assert.equal(x.rail.transfers,2);
    const refused=await cold({...inputB,wallet:{...inputB.wallet,policy:{...inputB.wallet.policy,max_amount:'0'}}});assert.equal(refused.code,1);assert.equal(refused.report.wallet_calls,0);assert.equal(x.rail.transfers,2);
    await mkdir('evidence/open-acquisition',{recursive:true});
    await writeFile('evidence/open-acquisition/recursive-chain.json',JSON.stringify({verified:true,environment:'TEST',chain:'A → Mark A → B → WHP Standing → Mark B',a:a.report,b:b.report,irrelevant_task:irrelevant.report,owner_refusal:refused.report,simulated_transfers:x.rail.transfers,independent_source_keys:true,no_source_whitelist:true,production_completion:false,live_funds:false,real_github_namespace_observation:false},null,2)+'\n');
  }finally{if(catalog)await new Promise(r=>catalog.close(r));await x.close();}
});

test('optional StandingBuyer uses the same open contract and cannot charge again on resume',async()=>{
  const x=await harness(),journal=new BuyerJournal(':memory:');try{
    const account=privateKeyToAccount('0x'+'04'.repeat(32));let calls=0;
    const policy={environment:'TEST',origin:x.service.origin,root_pin:x.f.rootPin,profile_hash:PROFILE_HASH,network:x.f.requirements.network,asset:x.f.requirements.asset,pay_to:x.f.requirements.payTo,payer:account.address,asset_name:x.f.requirements.extra.name,asset_version:x.f.requirements.extra.version,max_per_purchase:'1000000',max_total:'1000000'};
    const buyer=new StandingBuyer({policy,journal,paymentSigner:{async signTypedData(payer,data){calls++;assert.equal(payer,account.address);return account.signTypedData(data);}},verifyResult:pythonVerifier({rootPin:x.f.rootPin,allowTest:true,python})});
    const first=await buyer.purchase(x.a.submission),second=await buyer.purchase(x.a.submission);
    assert.equal(first.state,'VERIFIED');assert.equal(second.result_bytes,first.result_bytes);assert.equal(calls,1);assert.equal(x.rail.transfers,1);
  }finally{journal.close();await x.close();}
});

test('already-settled historical v1 rows recover with the frozen v1 assembly and verifier',async()=>{
  const x=await harness(),f=legacyFixture({at:now()}),at=now();try{
    const s=f.submission,id=hash({domain:'WHP-STANDING-PURCHASE-v1',root_pin:f.rootPin,buyer_key:s.buyer_key,client_reference:s.client_reference});
    const quote=seal('WHP-STANDING-QUOTE-v1',{purchase_id:id,request_hash:hash(s),buyer_key:s.buyer_key,profile_hash:s.profile.sha256,issuer:f.trustBundle.profile_authorization.payload.issuer,environment:'TEST',issued_at:at,expires_at:at+300,resource:{url:x.service.origin+'/v1/evaluations',description:'One historical assessment',mimeType:'application/json'},payment_requirements:f.requirements,charge_policy:'One historical evaluation'},f.issuer.privateKey);
    const payment={x402Version:2,resource:quote.payload.resource,accepted:f.requirements,payload:{signature:'0x'+'11'.repeat(64)+'1b',authorization:{from:'0x'+'33'.repeat(20),to:f.requirements.payTo,value:f.requirements.amount,validAfter:String(at-1),validBefore:String(at+240),nonce:authorizationNonce(quote)}}};
    const rail=new FakeRail();await rail.settle(payment);const settlement=await rail.reconcile({payment_payload:payment});
    const row={id,buyer_key:s.buyer_key,client_reference:s.client_reference,request_hash:hash(s),state:'SETTLED',submission:s,quote,trust_bundle:f.trustBundle,decision:legacyEvaluate(s,f.trustBundle,f.rootPin,at),issued_at:at,settlement,payment_payload:payment,payment_key:legacyValidatePayment(payment,quote,at),discovery_identity:{resolution_url:x.service.resolutionUrl}};
    await x.store.quote(row);x.service.privateKey=f.issuer.privateKey;x.service.rootPin=f.rootPin;
    const response=await fetch(x.service.origin+'/v1/purchases/'+id+'/recover',{method:'POST'});assert.equal(response.status,200,await response.clone().text());const bytes=await response.text();assert.equal(JSON.parse(bytes).protected.type,'WHP-STANDING-MARK-v1');
    assert.equal(await(await fetch(x.service.origin+'/v1/purchases/'+id+'/result')).text(),bytes);assert.equal(x.rail.transfers,0);
    const directory=await mkdtemp(join(tmpdir(),'legacy-proof-'));
    try{await writeFile(join(directory,'mark.json'),bytes);const program=JSON.parse(await readFile('legacy/v1/public/verifier-manifest.json')).path;const result=await new Promise((res,rej)=>{const p=spawn(python,['public'+program,join(directory,'mark.json'),'--root-pin',f.rootPin,'--allow-test','--at',String(at)]);let out='';p.stdout.on('data',b=>out+=b);p.on('error',rej);p.on('close',code=>res({code,out}));});assert.equal(result.code,0,result.out);assert.equal(JSON.parse(result.out).verified,true);}finally{await rm(directory,{recursive:true,force:true});}
  }finally{await x.close();}
});

test('eligibility cannot be supplied by a payment, another namespace, wrong key, changed payload or missing transformation grant',async()=>{
  const x=await harness();try{
    for(const mutate of [s=>s.authority=[],s=>s.authority=x.b.submission.authority,s=>{s.nodes[0].signature=s.nodes[0].signature.replace(/^./,s.nodes[0].signature[0]==='A'?'B':'A');}]){
      const s=structuredClone(x.a.submission);s.client_reference=randomHex(32);mutate(s);const q=await post(x,s);assert.equal(q.status,402);const terms=await q.json();assert.equal(terms.eligibility.can_produce_mark,false);
    }
    const m=structuredClone(x.a.manifest);m.grants=m.grants.filter(g=>g.role!=='TRANSITION');x.records.set(encodeURIComponent(m.namespace),m);
    const s=structuredClone(x.a.submission);s.client_reference=randomHex(32);s.authority[0].manifest_sha256=hash(m);
    const terms=await (await post(x,s)).json();assert.equal(terms.eligibility.can_produce_mark,false);assert.ok(terms.eligibility.failed_checks.some(c=>c.rule==='TRANSITION_AUTHORITY'));
    const paid=await post(x,s,await signTerms(terms));assert.equal(paid.status,200,await paid.clone().text());const bytes=await paid.text(),assessment=JSON.parse(bytes);assert.equal(assessment.payload.mark_id,null);assert.equal(assessment.payload.standing,null);
    const registry=await (await fetch(x.service.origin+'/v1/registry/'+terms.purchase_id)).text();const report=await pythonVerifier({rootPin:x.f.rootPin,allowTest:true,python})(bytes,registry,now());assert.equal(report.verified,true);assert.equal(report.assessment,'NOT_ESTABLISHED');
    assert.equal(x.rail.transfers,1);
    // Submitted origin cannot turn the authority observer into an arbitrary fetcher.
    const ssrf=structuredClone(s);ssrf.authority[0].namespace='http://127.0.0.1/private';ssrf.client_reference=randomHex(32);assert.equal((await post(x,ssrf)).status,400);
  }finally{await x.close();}
});

test('random-nonce payment stays with one exact purchase through concurrency, replay rejection, expiry and lost settlement response',async()=>{
  let time=now();const dir=await mkdtemp(join(tmpdir(),'open-recovery-')),filename=join(dir,'purchases.sqlite');
  const x=await harness({filename,clock:()=>time});try{
    const s=x.a.submission,terms=await (await post(x,s)).json(),payment=await signTerms(terms);
    const altered=structuredClone(s);altered.requested_operation='RECOMMEND';assert.equal((await post(x,altered,payment)).status,409);
    x.rail.reveal=false;x.rail.mode='timeout-after-transfer';
    const replies=await Promise.all([post(x,s,payment),post(x,s,payment)]);assert.ok(replies.every(r=>r.status===202));assert.equal(x.rail.transfers,1);
    const other=structuredClone(s);other.client_reference=randomHex(32);const replay=await post(x,other,payment);assert.equal(replay.status,409);assert.equal((await replay.json()).error.code,'PAYMENT_REPLAY');
    const issuer=x.service.privateKey,trust=x.service.trustBundle,rail=x.rail,origin=x.service.origin,pin=x.f.rootPin;
    await x.store.close();time+=800;const restarted=await setup({filename,f:x.f,rail,clock:()=>time});x.store=restarted.store;x.service.store=restarted.store;x.service.clock=()=>time;x.service.privateKey=issuer;x.service.trustBundle=trust;
    rail.reveal=true;
    const recovered=await fetch(origin+'/v1/purchases/'+terms.purchase_id+'/recover',{method:'POST'});assert.equal(recovered.status,200,await recovered.clone().text());const bytes=await recovered.text();
    assert.equal(await (await fetch(origin+'/v1/purchases/'+terms.purchase_id+'/result')).text(),bytes);assert.equal(await (await post(x,s,payment)).text(),bytes);assert.equal(rail.transfers,1);assert.equal(rail.settleCalls,1);
    const p=JSON.parse(bytes);assert.equal(p.payload.commerce.payment_payload.payload.authorization.nonce,payment.payload.authorization.nonce);assert.equal(p.payload.purchase_id,terms.purchase_id);
    const verify=pythonVerifier({rootPin:pin,allowTest:true,python});
    const registry=await (await fetch(origin+'/v1/registry/'+terms.purchase_id)).text();const verified=await verify(bytes,registry,time);assert.equal(verified.verified,true);assert.equal(verified.current_standing,'ACTIVE');
    const issuanceEvidence=p.payload.authority_evidence;assert.ok(issuanceEvidence[0].payload.observed_at<time-300);
    assert.equal(JSON.parse(registry).payload.authority_evidence[0].payload.observed_at,time);
    const namespace=encodeURIComponent(x.a.manifest.namespace);x.records.delete(namespace);
    const withdrawn=await (await fetch(origin+'/v1/registry/'+terms.purchase_id)).text();assert.equal((await verify(bytes,withdrawn,time)).current_standing,'LIMITED');
    x.records.set(namespace,x.a.manifest);
    const restored=await (await fetch(origin+'/v1/registry/'+terms.purchase_id)).text();assert.equal((await verify(bytes,restored,time)).current_standing,'ACTIVE');
    assert.equal(await (await fetch(origin+'/v1/purchases/'+terms.purchase_id+'/result')).text(),bytes);assert.equal(rail.transfers,1);
  }finally{await x.close();await rm(dir,{recursive:true,force:true});}
});

test('namespace and payment checks crossing clock boundaries use the completed observation time',async()=>{
  let time=now();const x=await harness({clock:()=>time});try{
    const observe=x.service.namespaceFetch;x.service.namespaceFetch=async(...args)=>{const result=await observe(...args);time+=2;return result;};
    const response=await post(x,x.a.submission);assert.equal(response.status,402,await response.clone().text());const terms=await response.json();assert.equal(terms.eligibility.can_produce_mark,true);
    const verify=x.rail.verify.bind(x.rail);x.rail.verify=async(...args)=>{const result=await verify(...args);time+=2;return result;};
    const paid=await post(x,x.a.submission,await signTerms(terms));assert.equal(paid.status,200,await paid.clone().text());const mark=await paid.json();assert.equal(mark.payload.decision_record.evaluated_at,time);
    assert.ok(mark.payload.authority_evidence[0].payload.observed_at<=mark.payload.decision_record.evaluated_at);
  }finally{await x.close();}
});

test('cold consumer resumes 202 with cumulative 402 evidence and one owner authorization',async()=>{
  const x=await harness(),directory=await mkdtemp(join(tmpdir(),'cold-recovery-'));let catalog;try{
    catalog=createServer((req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({providers:[{capability_class:STANDING_CAPABILITY.id,properties:STANDING_CAPABILITY.requirements,resolution_url:x.service.resolutionUrl}]}));});
    const input={...x.a.input,catalog_url:await listen(catalog)};x.rail.reveal=false;x.rail.mode='timeout-after-transfer';
    const pending=await cold(input,{directory});assert.equal(pending.code,0,JSON.stringify(pending));assert.equal(pending.report.pending,true);assert.equal(pending.report.wallet_calls,1);assert.equal(x.rail.transfers,1);
    x.rail.reveal=true;const recovered=await cold(input,{directory});assert.equal(recovered.code,0,JSON.stringify(recovered));assert.equal(recovered.report.acquired,true);assert.equal(recovered.report.wallet_calls,1);assert.equal(x.rail.transfers,1);
    assert.equal(recovered.report.trace.filter(e=>e.status===402).length,1);assert.ok(recovered.report.trace.some(e=>e.status===202));assert.ok(recovered.report.trace.some(e=>e.status===200&&e.url.endsWith('/recover')));
    const again=await cold(input,{directory});assert.equal(again.code,0,JSON.stringify(again));assert.equal(again.mark,recovered.mark);assert.equal(again.report.wallet_calls,1);assert.equal(x.rail.transfers,1);assert.equal(again.report.trace.filter(e=>e.status===402).length,1);
  }finally{if(catalog)await new Promise(r=>catalog.close(r));await x.close();await rm(directory,{recursive:true,force:true});}
});
