// Read-only observation after the matching v1.1 publication and deployment.
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {demand,parseStrict,hash,hashBytes} from '../src/canonical.mjs';
import {validateTrust} from '../src/authority.mjs';
import {PROFILE_HASH} from '../src/profile.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {target,api,ORIGIN,SITE_ID} from './netlify-production-target.mjs';
import {readApprovedPublicAuthority} from './open-authority-administration.mjs';

async function get(path){
  const r=await fetch(ORIGIN+path,{headers:{'cache-control':'no-cache'},redirect:'error',signal:AbortSignal.timeout(20000)});
  demand(r.status===200,'DEPLOYED_RESOURCE_HTTP_'+r.status);
  return r.text();
}

export async function observeDeployment(commit){
  demand(/^[0-9a-f]{40}$/.test(commit??''),'DEPLOYMENT_COMMIT_REQUIRED');
  const expected=await readApprovedPublicAuthority();
  let expectedId=process.env.EXPECTED_DEPLOY_ID??null;
  if(process.env.NETLIFY_DEPLOY_RESULT){
    const result=parseStrict(await readFile(process.env.NETLIFY_DEPLOY_RESULT,'utf8'),1048576);
    demand(result.site_id===SITE_ID&&typeof result.deploy_id==='string','DEPLOYMENT_RESULT_TARGET_MISMATCH');
    demand(!expectedId||expectedId===result.deploy_id,'DEPLOYMENT_ID_DISAGREEMENT');
    expectedId=result.deploy_id;
  }
  await target();
  let deployment=null;
  for(let attempt=0;attempt<36;attempt++){
    const s=await api('/sites/'+SITE_ID),d=s.published_deploy;
    if(d?.state==='ready'&&(expectedId?d.id===expectedId:d.commit_ref===commit)){deployment=d;break;}
    await new Promise(resolve=>setTimeout(resolve,10000));
  }
  demand(deployment,'CONNECTED_DEPLOYMENT_NOT_OBSERVED');
  if(deployment.commit_ref)demand(deployment.commit_ref===commit,'DEPLOYED_COMMIT_MISMATCH');
  let stamp=null;
  if(expectedId){
    const local=parseStrict(await readFile('public/deployment.json','utf8'),1048576);
    stamp=parseStrict(await get('/deployment.json'),1048576);
    demand(local.source_commit===commit&&hash(stamp)===hash(local),'DEPLOYED_SOURCE_STAMP_MISMATCH');
    demand(stamp.site_id===SITE_ID&&stamp.profile_sha256===PROFILE_HASH&&stamp.contract_sha256===CONTRACT_HASH&&stamp.verifier_sha256===VERIFIER_HASH,'DEPLOYED_SOURCE_COMMITMENTS_MISMATCH');
  }
  const [liveRaw,publicRaw,bundleRaw,contractRaw,verifierRaw,healthRaw]=await Promise.all([
    get('/.well-known/whp-standing.json'),get('/authority/root.json'),get('/authority/trust-bundle.json'),
    get('/v1/contract'),get('/verification/'+VERIFIER_HASH+'.py'),get('/healthz')]);
  const live=parseStrict(liveRaw,2000000),published=parseStrict(publicRaw,2000000),bundle=parseStrict(bundleRaw,1048576),contract=parseStrict(contractRaw,1048576),health=parseStrict(healthRaw);
  demand(hash(published)===hash(expected)&&hash(bundle)===hash(expected.trust_bundle),'DEPLOYED_PUBLIC_AUTHORITY_MISMATCH');
  demand(live.root_pin===expected.root_pin&&hash(live.trust_bundle)===hash(expected.trust_bundle),'DEPLOYED_RUNTIME_TRUST_MISMATCH');
  const trust=validateTrust(live.trust_bundle,expected.root_pin,Math.floor(Date.now()/1000));
  demand(trust.profile.environment==='LIVE'&&live.environment==='LIVE'&&hash(live.profile)===PROFILE_HASH,'DEPLOYED_PROFILE_MISMATCH');
  demand(contract.version==='WHP-STANDING-CONTRACT-v1.1'&&contract.profile.sha256===PROFILE_HASH&&contract.root_pin===expected.root_pin&&contract.authentication.purchase==='NONE_BEYOND_X402_PAYMENT'&&contract.payment.required_extension===null,'DEPLOYED_OPEN_CONTRACT_MISMATCH');
  demand(contract.public_contract.sha256===CONTRACT_HASH&&hash(contract.public_contract.document)===CONTRACT_HASH&&contract.public_contract.verifier_sha256===VERIFIER_HASH,'DEPLOYED_CONTRACT_COMMITMENT_MISMATCH');
  demand(hashBytes(verifierRaw)===VERIFIER_HASH,'DEPLOYED_VERIFIER_MISMATCH');
  demand(health.service==='WHP Standing'&&health.live_completion_proven===false,'RUNTIME_HEALTH_CLAIM_MISMATCH');
  const result={checked_at:new Date().toISOString(),deployed_commit:commit,source_tree:stamp?.source_tree??null,
    deployment_commit_attribution:deployment.commit_ref?'NETLIFY_GIT_COMMIT':'WORKFLOW_DEPLOY_ID_AND_EXACT_PUBLIC_STAMP',
    deployment_id:deployment.id,site_id:SITE_ID,origin:ORIGIN,root_pin:live.root_pin,
    profile_sha256:PROFILE_HASH,contract_sha256:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,
    runtime_trust_bundle_sha256:hash(live.trust_bundle),runtime_status_sequence:live.trust_bundle.status_snapshot.payload.sequence,
    status_valid_until:live.trust_bundle.status_snapshot.payload.valid_until,public_status_matches_runtime:true,
    production_function_refreshed:true,health_status:200,payment_executed:false,live_mark_issued:false,production_completion:false};
  await mkdir('artifacts',{recursive:true});
  await writeFile('artifacts/authority-deployment.json',JSON.stringify(result,null,2)+'\n');
  return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{console.log(JSON.stringify(await observeDeployment(process.env.EXPECTED_DEPLOY_COMMIT)));}
  catch(e){console.error('AUTHORITY_DEPLOYMENT_OBSERVATION_STOPPED',e.code??'SAFE_INTERNAL_FAILURE');process.exitCode=1;}
}
