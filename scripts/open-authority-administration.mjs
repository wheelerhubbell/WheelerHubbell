// Administration of the already-ratified v1.1 epoch. No key establishment.
// prepare writes public staging files only. Remote administration verifies the
// signed rules and full TEST gate before reading credentials. LIVE completion is
// checked only after deployment; it is never asserted by this adapter.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {canonical,parseStrict,hash,hashBytes,keyId,publicDer,seal,openSeal,demand} from '../src/canonical.mjs';
import {validateTrust,issuerAuthority} from '../src/authority.mjs';
import {validateTrust as validatePreviousTrust} from '../legacy/v1/src/authority.mjs';
import {PROFILE_HASH} from '../src/profile.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {target,variable,value,put,ORIGIN} from './netlify-production-target.mjs';

const RATIFICATION='public/authority/ratifications/open-acquisition-v1.1/root.json';
const ROOT_PIN='e3a0a2945081823171841bde32a6df7fc505b6f0b3e6ab9b6c85ecc9f3d49bfc';
const ISSUER_ID='8d65f5a4057eedb76ac3db83e9217a374c0072adfa3986b4745e4b5b5bbb22e8';
const HISTORICAL_ORIGIN='https://wheelerhubbellpublishingstandingmark.netlify.app';
const now=()=>Math.floor(Date.now()/1000);
const read=async path=>parseStrict(await readFile(path,'utf8'),1048576);
const rules=b=>({...b,status_snapshot:null});
const statusTime=(b,at)=>Math.max(b.status_snapshot.payload.valid_from,Math.min(at,b.status_snapshot.payload.valid_until-1));

function issuer(bundle,at){
  const trust=validateTrust(bundle,ROOT_PIN,at);
  demand(trust.profile.environment==='LIVE','LIVE_AUTHORITY_REQUIRED');
  issuerAuthority(ISSUER_ID,'https://github.com/independent-controller/records','namespace-control',trust);
  issuerAuthority(ISSUER_ID,'whp-standing-structured-passage','protocol-structural-assessment-only',trust);
  return trust;
}

async function approved(){
  const publication=await read(RATIFICATION),b=publication.trust_bundle;
  demand(publication.root_pin===ROOT_PIN&&keyId(publication.root_public_key)===ROOT_PIN&&publication.issuer_key_id===ISSUER_ID,'EXISTING_IDENTITY_REQUIRED');
  const act=openSeal(publication.authorization_act,'WHP-EXISTING-ROOT-RATIFICATION-v1.1',publication.root_public_key);
  demand(act.root_pin===ROOT_PIN&&act.issuer_key_id===ISSUER_ID&&act.canonical_origin===ORIGIN&&publication.canonical_origin===ORIGIN,'RATIFICATION_IDENTITY_MISMATCH');
  demand(act.existing_root_preserved===true&&act.existing_issuer_preserved===true&&act.source_or_transition_authority_granted===false,'EXISTING_AUTHORITY_ONLY');
  demand(act.profile.sha256===PROFILE_HASH&&act.contract_sha256===CONTRACT_HASH&&act.verifier_sha256===VERIFIER_HASH,'RATIFIED_RULES_MISMATCH');
  demand(hash(b)===act.trust_bundle_sha256&&b.root_public_key===publication.root_public_key,'RATIFIED_BUNDLE_MISMATCH');
  issuer(b,act.ratified_at);
  demand(hash(await read('public/authority/ratifications/open-acquisition-v1.1/trust-bundle.json'))===hash(b),'RATIFICATION_FILES_DISAGREE');
  demand(hashBytes(await readFile('verify/verify_mark.py'))===VERIFIER_HASH,'VERIFIER_BYTES_MISMATCH');
  return {publication,act,bundle:b};
}

function candidate(bundle,approval,at=now()){
  demand(hash(rules(bundle))===hash(rules(approval.bundle)),'RATIFIED_AUTHORITY_CHANGED');
  issuer(bundle,at);
  const s=bundle.status_snapshot.payload,initial=approval.bundle.status_snapshot;
  demand(s.sequence>=initial.payload.sequence,'STATUS_ROLLBACK');
  if(s.sequence===initial.payload.sequence)demand(hash(bundle.status_snapshot)===hash(initial),'STATUS_SEQUENCE_CONFLICT');
  else demand(typeof s.previous_hash==='string'&&/^[0-9a-f]{64}$/.test(s.previous_hash),'STATUS_CHAIN_REQUIRED');
}

async function previous(approval){
  const name=approval.act.previous_public_authority_sha256;
  let raw=await readFile('public/authority/root.json','utf8');
  if(hash(parseStrict(raw,1048576))!==name)raw=await readFile('public/authority/history/'+name+'.json','utf8');
  const publication=parseStrict(raw,1048576);
  demand(hash(publication)===name&&publication.root_pin===ROOT_PIN&&publication.issuer_key_id===ISSUER_ID,'EXPECTED_PREVIOUS_AUTHORITY_REQUIRED');
  validatePreviousTrust(publication.trust_bundle,ROOT_PIN,statusTime(publication.trust_bundle,now()));
  let trustRaw=await readFile('public/authority/trust-bundle.json','utf8');
  if(hash(parseStrict(trustRaw,1048576))!==hash(publication.trust_bundle))trustRaw=await readFile('public/authority/history/'+name+'.trust-bundle.json','utf8');
  demand(hash(parseStrict(trustRaw,1048576))===hash(publication.trust_bundle),'PREVIOUS_PUBLIC_FILES_DISAGREE');
  return {publication,raw,trustRaw,name};
}

function preparedPublication(approval,bundle,prior){
  const {current_production_authority_replaced,...publication}=approval.publication;
  return {...publication,trust_bundle:bundle,production_activation_requires:'Matching existing-root authorization, runtime configuration and successful open-acquisition TEST gate.',
    production_completion_requires:'After deployment, the unchanged LIVE release gate must verify the real paid A-to-B chain.',
    historical_authority_url:ORIGIN+'/authority/history/'+prior.name+'.json',
    authorization_ratification_url:ORIGIN+'/authority/ratifications/open-acquisition-v1.1/root.json'};
}

async function immutableWrite(path,bytes){
  demand(!bytes.includes('PRIVATE KEY'),'PRIVATE_MATERIAL_IN_PUBLIC_OUTPUT');
  try{await writeFile(path,bytes,{flag:'wx'});}catch(e){if(e.code!=='EEXIST')throw e;demand(await readFile(path,'utf8')===bytes,'PREPARED_FILE_CONFLICT');}
}

async function stage(directory,approval,bundle,prior){
  candidate(bundle,approval);
  const dir=resolve(directory),publicDir=resolve('public');
  demand(dir!==publicDir&&!dir.startsWith(publicDir+'/'),'SEPARATE_PREPARATION_DIRECTORY_REQUIRED');
  await mkdir(join(dir,'history'),{recursive:true});
  await immutableWrite(join(dir,'history',prior.name+'.json'),prior.raw);
  await immutableWrite(join(dir,'history',prior.name+'.trust-bundle.json'),prior.trustRaw);
  const current=await publicCandidate(approval,prior);
  if(current&&hash(current.bundle)!==hash(bundle)){
    await immutableWrite(join(dir,'history',hash(current.publication)+'.json'),current.raw);
    await immutableWrite(join(dir,'history',hash(current.publication)+'.trust-bundle.json'),current.trustRaw);
  }
  await immutableWrite(join(dir,'root.json'),canonical(preparedPublication(approval,bundle,prior))+'\n');
  await immutableWrite(join(dir,'trust-bundle.json'),canonical(bundle)+'\n');
  return {prepared:true,directory:dir,root_pin:ROOT_PIN,issuer_key_id:ISSUER_ID,trust_bundle_sha256:hash(bundle),status_sequence:bundle.status_snapshot.payload.sequence,production_configuration_changed:false,deployed:false,production_completion:false};
}

async function publicCandidate(approval,prior){
  const raw=await readFile('public/authority/root.json','utf8'),publication=parseStrict(raw,1048576);
  if(hash(publication)===prior.name)return null;
  const bundle=publication.trust_bundle;
  candidate(bundle,approval,statusTime(bundle,now()));
  demand(hash(publication)===hash(preparedPublication(approval,bundle,prior)),'CURRENT_PUBLICATION_MISMATCH');
  const trustRaw=await readFile('public/authority/trust-bundle.json','utf8');
  demand(hash(parseStrict(trustRaw,1048576))===hash(bundle),'CURRENT_PUBLIC_FILES_DISAGREE');
  return {publication,bundle,raw,trustRaw};
}

export async function readApprovedPublicAuthority(){
  const approval=await approved(),prior=await previous(approval),current=await publicCandidate(approval,prior);
  demand(current,'PUBLISHED_CANDIDATE_REQUIRED');
  candidate(current.bundle,approval);
  return current.publication;
}

function deploymentGate(){
  try{execFileSync('npm',['run','check:open-acquisition'],{stdio:'inherit',env:process.env});}
  catch{demand(false,'OPEN_ACQUISITION_GATE_REQUIRED');}
}

async function runtime(site,approval,prior){
  const [root,issuerRow,bundleRow,origin]=await Promise.all(['WHP_ROOT_PIN','WHP_ISSUER_PRIVATE_KEY','WHP_TRUST_BUNDLE_JSON','WHP_ORIGIN'].map(k=>variable(site,k)));
  const rootValue=value(root),originValue=value(origin);
  if(rootValue!==undefined)demand(rootValue===ROOT_PIN,'RUNTIME_ROOT_IDENTITY_MISMATCH');
  if(originValue!==undefined)demand(originValue===ORIGIN||originValue===HISTORICAL_ORIGIN,'RUNTIME_ORIGIN_MISMATCH');
  demand(issuerRow?.values?.length===1&&issuerRow.values[0].context==='production','ISSUER_PRODUCTION_CUSTODY_REQUIRED');
  demand(keyId(publicDer(value(issuerRow)))===ISSUER_ID,'EXISTING_ISSUER_MISMATCH');
  const bundle=parseStrict(value(bundleRow),1048576);
  demand(keyId(bundle.root_public_key)===ROOT_PIN,'RUNTIME_ROOT_BUNDLE_MISMATCH');
  if(hash(rules(bundle))===hash(rules(approval.bundle))){candidate(bundle,approval,statusTime(bundle,now()));return {bundle,epoch:'candidate',needs_root_pin:rootValue!==ROOT_PIN,needs_origin:originValue!==ORIGIN};}
  demand(hash(rules(bundle))===hash(rules(prior.publication.trust_bundle)),'UNRELATED_RUNTIME_AUTHORITY');
  validatePreviousTrust(bundle,ROOT_PIN,statusTime(bundle,now()));
  const s=bundle.status_snapshot.payload,old=prior.publication.trust_bundle.status_snapshot;
  demand(s.sequence>=old.payload.sequence,'PREVIOUS_STATUS_ROLLBACK');
  if(s.sequence===old.payload.sequence)demand(hash(bundle.status_snapshot)===hash(old),'PREVIOUS_STATUS_CONFLICT');
  return {bundle,epoch:'previous',needs_root_pin:rootValue!==ROOT_PIN,needs_origin:originValue!==ORIGIN};
}

function follows(next,current,approval){
  const base=current.epoch==='previous'?approval.bundle:current.bundle;
  if(hash(next)!==hash(base)){
    const s=next.status_snapshot.payload,old=base.status_snapshot;
    demand(s.sequence===old.payload.sequence+1&&s.previous_hash===hash(old),'NEXT_STATUS_SNAPSHOT_REQUIRED');
  }
}

async function installBundle(site,bundle,approval,prior,expected){
  candidate(bundle,approval);
  const current=await runtime(site,approval,prior);
  demand(hash(current.bundle)===hash(expected.bundle),'RUNTIME_AUTHORITY_CHANGED');
  follows(bundle,current,approval);
  if(current.needs_root_pin)await put(site,'WHP_ROOT_PIN',ROOT_PIN,'production');
  if(current.needs_origin)await put(site,'WHP_ORIGIN',ORIGIN,'production');
  await put(site,'WHP_TRUST_BUNDLE_JSON',canonical(bundle),'production');
  const back=await variable(site,'WHP_TRUST_BUNDLE_JSON');
  demand(back?.values?.length===1&&back.values[0].context==='production'&&hash(parseStrict(value(back),1048576))===hash(bundle),'AUTHORITY_INSTALL_READBACK_FAILED');
  const normalized=await runtime(site,approval,prior);
  demand(!normalized.needs_root_pin&&!normalized.needs_origin,'RUNTIME_IDENTITY_NORMALIZATION_FAILED');
  return {production_configuration_changed:hash(bundle)!==hash(current.bundle)||current.needs_root_pin||current.needs_origin,runtime_configuration_readback_verified:true,root_pin:ROOT_PIN,issuer_key_id:ISSUER_ID,trust_bundle_sha256:hash(bundle),status_sequence:bundle.status_snapshot.payload.sequence,private_keys_changed:false,deployed:false,production_completion:false};
}

export async function administer(mode,directory,custodyOverride=null){
  demand(['prepare','install','renew','sync'].includes(mode)&&directory,'PREPARE_INSTALL_RENEW_OR_SYNC_AND_DIRECTORY_REQUIRED');
  const approval=await approved(),prior=await previous(approval);
  const published=await publicCandidate(approval,prior);
  if(mode==='prepare')return stage(directory,approval,published?.bundle??approval.bundle,prior);
  deploymentGate();
  const site=await target(),current=await runtime(site,approval,prior);
  if(mode==='install'){
    const bundle=await read(join(directory,'trust-bundle.json')),publication=await read(join(directory,'root.json'));
    candidate(bundle,approval);
    demand(hash(publication)===hash(preparedPublication(approval,bundle,prior)),'PREPARED_PUBLICATION_MISMATCH');
    demand(await readFile(join(directory,'history',prior.name+'.json'),'utf8')===prior.raw&&await readFile(join(directory,'history',prior.name+'.trust-bundle.json'),'utf8')===prior.trustRaw,'PREPARED_HISTORY_MISMATCH');
    return installBundle(site,bundle,approval,prior,current);
  }
  if(mode==='renew')demand(current.epoch==='candidate','ACTIVE_CANDIDATE_REQUIRED_FOR_RENEWAL');
  const bundle=structuredClone(current.epoch==='candidate'?current.bundle:approval.bundle),old=bundle.status_snapshot,at=now();
  if(published){
    demand(current.epoch==='candidate','PUBLISHED_CANDIDATE_REQUIRES_MATCHING_RUNTIME');
    const s=current.bundle.status_snapshot.payload,p=published.bundle.status_snapshot;
    demand(s.sequence>=p.payload.sequence,'RUNTIME_STATUS_ROLLBACK');
    if(s.sequence===p.payload.sequence)demand(hash(old)===hash(p),'RUNTIME_PUBLIC_STATUS_CONFLICT');
    else demand(s.sequence===p.payload.sequence+1&&s.previous_hash===hash(p),'RUNTIME_PUBLIC_STATUS_CHAIN_MISMATCH');
  }
  if(mode==='sync'&&old.payload.valid_until>=at+64800){
    await stage(directory,approval,bundle,prior);
    return {...await installBundle(site,bundle,approval,prior,current),prepared_directory:resolve(directory),status_renewed:false};
  }
  let custody=custodyOverride;
  if(!custody){
    const record=await variable(site,'WHP_AUTHORITY_CUSTODY_V2');
    demand(record?.values?.length===1&&record.values[0].context==='dev','EXISTING_DEV_CUSTODY_REQUIRED');
    custody=parseStrict(value(record,'dev'),1048576);
  }
  demand(custody.root_pin===ROOT_PIN&&custody.issuer_key_id===ISSUER_ID&&keyId(publicDer(custody.root_private_key))===ROOT_PIN&&keyId(publicDer(custody.issuer_private_key))===ISSUER_ID,'EXISTING_CUSTODY_IDENTITY_MISMATCH');
  const until=Math.min(at+86400,bundle.profile_authorization.payload.valid_until,...bundle.certificates.map(c=>c.payload.valid_until));
  demand(until>at+3600,'EXISTING_AUTHORITY_EXPIRES_SOON');
  bundle.status_snapshot=seal('WHP-TRUST-STATUS-v1',{...old.payload,sequence:old.payload.sequence+1,previous_hash:hash(old),valid_from:at-30,valid_until:until},custody.root_private_key);
  candidate(bundle,approval,at);
  await stage(directory,approval,bundle,prior);
  if(current.epoch==='candidate'&&(!published||hash(current.bundle)!==hash(published.bundle))){
    const publication=preparedPublication(approval,current.bundle,prior),name=hash(publication);
    await immutableWrite(join(resolve(directory),'history',name+'.json'),canonical(publication)+'\n');
    await immutableWrite(join(resolve(directory),'history',name+'.trust-bundle.json'),canonical(current.bundle)+'\n');
  }
  return {...await installBundle(site,bundle,approval,prior,current),prepared_directory:resolve(directory),status_renewed:true,profile_authorization_changed:false,certificates_changed:false,revocations_changed:false};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{console.log(JSON.stringify(await administer(process.argv[2],process.argv[3])));}
  catch(e){console.error(JSON.stringify({administration_completed:false,error:e.code??'AUTHORITY_ADMINISTRATION_FAILED',deployed:false}));process.exitCode=1;}
}
