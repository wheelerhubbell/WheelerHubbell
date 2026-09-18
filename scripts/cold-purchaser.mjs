// Generic capability consumer; LIVE requires independently admitted root and owner wallet runtime. No provider URL, producer module or client library.
import {readFile,writeFile,mkdir,mkdtemp,rm,rename} from 'node:fs/promises';
import {createHash,createPublicKey,verify,randomBytes} from 'node:crypto';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {x402Client} from '@x402/core/client';
import {wrapFetchWithPayment} from '@x402/fetch';
import {ExactEvmScheme} from '@x402/evm/exact/client';
import {privateKeyToAccount} from 'viem/accounts';

const demand=(ok,code)=>{if(!ok)throw Error(code);};
function canonical(x){if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';if(x&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';return JSON.stringify(x);}
const sha=x=>createHash('sha256').update(x).digest('hex'),hash=x=>sha(canonical(x));
const trace=[];let walletCalls=0,purchase=null,job=null;
const input=JSON.parse(await readFile(process.argv[2],'utf8'));
const root=process.cwd();
async function checkpoint(name,value){const path=join(root,name);await writeFile(path+'.next',JSON.stringify(value),{mode:0o600,flush:true});await rename(path+'.next',path);}
async function saveJob(){if(job){job.trace=trace;job.wallet_calls=walletCalls;await checkpoint('job.json',job);}}
function signature(e,type,pub){demand(e.protected.type===type&&e.protected.algorithm==='Ed25519','SIGNATURE_TYPE');const der=Buffer.from(pub,'base64');demand(sha(der)===e.protected.key_id,'SIGNATURE_KEY');demand(verify(null,Buffer.from(canonical({protected:e.protected,payload:e.payload})),createPublicKey({key:der,format:'der',type:'spki'}),Buffer.from(e.signature,'base64')),'SIGNATURE_INVALID');return e.payload;}
async function request(url,options={}){
  const address=url instanceof Request?url.url:url;const u=new URL(address);demand(u.protocol==='https:'||u.protocol==='http:'&&u.hostname==='127.0.0.1','TRANSPORT_ORIGIN');
  const response=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(20000)});
  trace.push({method:options.method??(url instanceof Request?url.method:'GET'),url:address,status:response.status});await saveJob();return response;
}
async function document(url,expected){const r=await request(url);demand(r.ok,'DOCUMENT_UNAVAILABLE');const d=await r.json();if(expected)demand(hash(d)===expected,'DOCUMENT_HASH');return d;}
function bootstrap(resolution,manifest,programHash,pin){
  const p=resolution.payload,b=p.trust_bundle,t=Math.floor(Date.now()/1000),recipe=manifest.bootstrap;
  demand(p.environment==='TEST'||p.environment==='LIVE'&&input.trust_policy?.root_pins?.includes(pin),'LIVE_OWNER_AND_ROOT_POLICY_REQUIRED');
  demand(sha(Buffer.from(b.root_public_key,'base64'))===pin&&p.root_key_id===pin,'ROOT_SUBSTITUTION');
  const a=signature(b.profile_authorization,recipe.authorization_type,b.root_public_key);
  demand(a.ratified&&a.contract_hash===hash(manifest)&&a.verifier_sha256===programHash&&a.profile_hash===manifest.profile.sha256&&a.valid_from<=t&&t<a.valid_until,'CONTRACT_AUTHORIZATION');
  const status=signature(b.status_snapshot,recipe.trust_status_type,b.root_public_key);
  demand(status.valid_from<=t&&t<status.valid_until&&status.certificates_hash===hash(b.certificates)&&status.profile_authorization_hash===hash(b.profile_authorization)&&status.revocations_hash===hash(b.revocations),'TRUST_STATUS');
  const certs=b.certificates.map(e=>signature(e,recipe.certificate_type,b.root_public_key));
  const c=certs.find(c=>sha(Buffer.from(c.public_key,'base64'))===resolution.protected.key_id);
  demand(c&&c.roles.includes(recipe.resolution_role)&&c.valid_from<=t&&t<c.valid_until,'RESOLUTION_ROLE');
  demand(!b.revocations.map(e=>signature(e,recipe.revocation_type,b.root_public_key)).some(r=>r.key_id===resolution.protected.key_id&&r.effective_at<=t),'RESOLUTION_REVOKED');
  signature(resolution,recipe.resolution_type,c.public_key);
  demand(p.observed_at<=t+30&&t<p.valid_until&&p.valid_until<=p.observed_at+300,'RESOLUTION_STALE');
}
async function sandbox(code,files,args){
  const directory=await mkdtemp(join(root,'public-verification-'));
  try{
    for(const [name,value] of Object.entries({...files,'verifier.py':code})){demand(!name.includes('/'),'INPUT_FILENAME');await writeFile(join(directory,name),value);}
    const output=await new Promise((resolve,reject)=>{
      const p=spawn(process.env.GENERIC_PYTHON,[process.env.GENERIC_SANDBOX,directory,...args],{env:{PATH:process.env.PATH},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
      const timer=setTimeout(()=>{p.kill('SIGKILL');reject(Error('VERIFIER_TIMEOUT'));},30000);
      p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('error',reject);p.on('close',code=>{clearTimeout(timer);if(code===0)resolve(stdout);else reject(Error('INDEPENDENT_VERIFICATION_FAILED: '+stdout+stderr));});
    });return JSON.parse(output);
  }finally{await rm(directory,{recursive:true,force:true});}
}
async function resolveCapability(url,mark=null){
  const resolution=await document(url),p=resolution.payload,locations=Object.fromEntries(p.artifacts.map(x=>[x.kind,x]));
  if(mark){const x=mark.payload.discovery;for(const k of ['root_key_id','capability_id','capability_class','resolution_id'])demand(p[k]===x[k],'DISCOVERY_SUBSTITUTION');}
  for(const x of Object.values(locations))demand(new URL(x.url).origin===p.service_origin,'ARTIFACT_ORIGIN');
  const manifest=mark?.payload.protocol.document??await document(locations.CONTRACT.url,locations.CONTRACT.sha256);
  const programHash=mark?.payload.protocol.verifier_sha256??locations.VERIFIER.sha256;
  demand(hash(manifest)===locations.CONTRACT.sha256&&programHash===locations.VERIFIER.sha256,'PROTOCOL_COMMITMENT');
  bootstrap(resolution,manifest,programHash,mark?.payload.discovery.root_key_id??p.root_key_id);
  const code=await (await request(locations.VERIFIER.url)).text();demand(sha(code)===programHash,'VERIFIER_SUBSTITUTION');
  const report=await sandbox(code,{'resolution.json':JSON.stringify(resolution),'contract.json':JSON.stringify(manifest)},['/input/resolution.json','--resolution-only','--contract','/input/contract.json','--root-pin',p.root_key_id,...(p.environment==='TEST'?['--allow-test']:[])]);
  demand(report.verified,'RESOLUTION_VERIFY_FAILED');
  const contract=await document(p.service_contract.url,p.service_contract.sha256);
  demand(contract.capability_class===input.task.capability_class&&contract.public_contract.sha256===hash(manifest),'CAPABILITY_MISMATCH');
  return {resolution,manifest,code,contract};
}
async function verifyArtifact(raw,resolved){
  const mark=JSON.parse(raw),p=mark.payload,r=resolved.resolution.payload;
  const registry=await document(r.registry_template.replace('{purchase_id}',p.purchase_id));
  const report=await sandbox(resolved.code,{'artifact.json':raw,'registry.json':JSON.stringify(registry),'resolution.json':JSON.stringify(resolved.resolution)},['/input/artifact.json','--registry','/input/registry.json','--resolution','/input/resolution.json','--root-pin',p.discovery.root_key_id,...(p.environment==='TEST'?['--allow-test']:[])]);
  await writeFile(join(root,'registry.json'),JSON.stringify(registry));
  demand(report.verified&&report.current_standing==='ACTIVE'&&report.assessment==='ESTABLISHED','MARK_NOT_VERIFIED');return report;
}
async function run(){
  // Relevance comes solely from this machine's task. A received artifact supplies discovery.
  if(!input.task.required){return {acquired:false,reason:'TASK_DOES_NOT_REQUIRE_CAPABILITY',wallet_calls:0,trace};}
  try{job=JSON.parse(await readFile(join(root,'job.json'),'utf8'));demand(job.input_hash===hash(input),'JOB_INPUT_CHANGED');}catch(e){if(e.code!=='ENOENT')throw e;}
  job??={input_hash:hash(input),wallet_calls:0,trace:[],milestones:{}};
  walletCalls=job.wallet_calls;trace.push(...(job.trace??[]));job.milestones??={};await saveJob();
  let savedPayment=null;try{savedPayment=JSON.parse(await readFile(join(root,'saved-payment.json'),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
  if(savedPayment){demand(job.submission&&hash(savedPayment.submission)===hash(job.submission),'RECOVERY_SUBMISSION_CHANGED');purchase=savedPayment.purchase;}
  let resolved,encountered=null;
  if(input.interaction){
    const raw=input.interaction.result._meta.signed_artifacts.map(s=>Buffer.from(s,'base64').toString()).find(s=>JSON.parse(s).payload?.discovery?.capability_class===input.task.capability_class);
    demand(raw,'RELEVANT_ARTIFACT_NOT_FOUND');const mark=JSON.parse(raw);
    resolved=await resolveCapability(mark.payload.discovery.resolution_url,mark);
    demand(mark.payload.object.id!==input.object.id,'UNRELATED_OBJECT_REQUIRED');
    // An already authorized purchase resumes the exact admission made before payment.
    // Initial admission still requires an independently verified ACTIVE encountered Mark.
    const admission=job.encountered_admission;
    if(savedPayment&&admission){
      demand(admission.mark_sha256===sha(raw)&&admission.task_sha256===hash(input.task)&&savedPayment.encountered_admission&&hash(savedPayment.encountered_admission)===hash(admission),'RECOVERY_ENCOUNTER_CHANGED');
      demand(admission.verification.verified&&admission.verification.current_standing==='ACTIVE'&&admission.verification.assessment==='ESTABLISHED','RECOVERY_ADMISSION_INVALID');
      encountered=admission.verification;
    }else{
      encountered=await verifyArtifact(raw,resolved);
      job.encountered_admission={mark_sha256:sha(raw),task_sha256:hash(input.task),verification:encountered};await saveJob();
    }
  }else{
    const catalog=await document(input.catalog_url+'?capability_class='+encodeURIComponent(input.task.capability_class));
    const candidate=catalog.providers.find(p=>p.capability_class===input.task.capability_class&&input.task.properties.every(k=>p.properties.includes(k)));
    demand(candidate,'NO_RELEVANT_PROVIDER');resolved=await resolveCapability(candidate.resolution_url);
  }
  const {contract}=resolved,offer=contract.purchase;
  demand(input.task.properties.every(k=>contract.supported_properties.includes(k)),'REQUIRED_PROPERTIES_MISSING');
  const schema=await document(offer.input_schema,offer.input_schema_sha256),properties=schema.$defs.submission.properties;
  const submission=job.submission??{version:properties.version.const,client_reference:randomBytes(32).toString('hex'),profile:schema.$defs.profile_ref.const,object:input.object,bounds:input.bounds,requested_operation:input.task.operation,nodes:input.nodes,transitions:input.transitions,authority:input.authority};
  const environment=resolved.resolution.payload.environment,policy=input.wallet.policy;
  job.submission=submission;await saveJob();
  let account;
  if(environment==='TEST')account=privateKeyToAccount(input.wallet.test_key);
  else{demand(!input.wallet.test_key&&process.env.GENERIC_OWNER_WALLET_MODULE,'EXISTING_OWNER_WALLET_RUNTIME_REQUIRED');const module=await import(process.env.GENERIC_OWNER_WALLET_MODULE);account=await module.default(policy);demand(account.address.toLowerCase()===policy.payer.toLowerCase()&&typeof account.signTypedData==='function','OWNER_WALLET_IDENTITY');}
  const signer={address:account.address,async signTypedData(data){
    demand(walletCalls===0,'SECOND_PAYMENT_FORBIDDEN');
    demand(BigInt(data.message.value)<=BigInt(policy.max_amount)&&data.message.to.toLowerCase()===policy.pay_to.toLowerCase()&&data.domain.verifyingContract.toLowerCase()===policy.asset.toLowerCase()&&String(data.domain.chainId)===policy.chain_id,'OWNER_SPENDING_POLICY');
    walletCalls++;await saveJob();return account.signTypedData(data);
  }};
  const client=new x402Client().setSpendControls({allowedAssets:[{network:'eip155:'+policy.chain_id,asset:policy.asset,maxAmountPerPayment:policy.max_amount}]}).register('eip155:'+policy.chain_id,new ExactEvmScheme(signer));
  client.onAfterPaymentCreation(async({paymentPayload})=>{await checkpoint('saved-payment.json',{submission,paymentPayload,purchase,encountered_admission:job.encountered_admission??null});});
  const paidFetch=wrapFetchWithPayment(async(url,options)=>{
    const response=await request(url,options);
    if(response.status===402){const terms=await response.clone().json();demand(terms.eligibility.can_produce_mark,'ELIGIBILITY_NOT_ESTABLISHED');purchase={id:terms.purchase_id,...terms.recovery};await checkpoint('purchase.json',purchase);job.milestones.quoted??={trace_index:trace.length-1,purchase_id:purchase.id};await saveJob();}
    return response;
  },client);
  let response;
  if(savedPayment){
    demand(hash(savedPayment.submission)===hash(submission),'RECOVERY_SUBMISSION_CHANGED');purchase=savedPayment.purchase;
    response=await request(purchase.result_url);
    if(response.status===202){const status=await response.clone().json();response=status.state==='QUOTED'?await request(offer.url,{method:'POST',headers:{'content-type':'application/json','payment-signature':Buffer.from(JSON.stringify(savedPayment.paymentPayload)).toString('base64')},body:JSON.stringify(submission)}):await request(purchase.recover_url,{method:'POST'});}
  }else{demand(walletCalls===0,'SIGNATURE_INTERRUPTED_BEFORE_DURABLE_PAYMENT; owner runtime must recover the original signature');response=await paidFetch(offer.url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(submission)});}
  if(response.status===202)return {acquired:false,pending:true,purchase_id:purchase.id,wallet_calls:walletCalls,additional_charge:false,trace,milestones:job.milestones};

  demand(response.status===200,'RESULT_NOT_RETURNED:'+response.status+':'+await response.clone().text());
  const resultTraceIndex=trace.length-1;
  const raw=await response.text(),mark=JSON.parse(raw);
  demand(hash(mark.payload.submission)===hash(submission)&&mark.payload.purchase_id===purchase.id,'OWN_OBJECT_BINDING');
  const verification=await verifyArtifact(raw,resolved);
  const retrieved=await (await request(purchase.result_url)).text();demand(retrieved===raw,'DURABLE_BYTES_CHANGED');
  await writeFile(join(root,'mark.json'),raw);
  job.milestones.verified_result={trace_index:resultTraceIndex,purchase_id:purchase.id,mark_sha256:sha(raw)};await saveJob();
  return {acquired:true,environment,root_admission:environment==='TEST'?'TEST_SELF_CONSISTENCY_ONLY':'OWNER_ADMITTED_ROOT_POLICY',institutional_authentication:environment==='LIVE',wallet_calls:walletCalls,encountered,encountered_admission:job.encountered_admission??null,verification,purchase_id:purchase.id,object_id:submission.object.id,source_keys:submission.nodes.map(e=>e.protected.key_id),trace,milestones:job.milestones,production_completion:false,provider_prior_configuration:false,client:'@x402/fetch + @x402/evm',sandbox:'seccomp syscall allowlist; no filesystem opens, network or process creation; in-memory public artifacts only'};
}
try{console.log(JSON.stringify(await run()));}catch(e){console.log(JSON.stringify({acquired:false,error:e.message,wallet_calls:walletCalls,trace}));process.exitCode=1;}
