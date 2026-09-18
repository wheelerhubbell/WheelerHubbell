// Existing-root v1.1 administration only. Never generates, rotates, or migrates private keys.
import {copyFile,mkdir,readdir,rm,readFile,writeFile} from 'node:fs/promises';
import {canonical,parseStrict,demand,hash,keyId,publicDer,seal,openSeal,randomHex} from '../src/canonical.mjs';
import {api,target,variable,value,ORIGIN} from './netlify-production-target.mjs';
import {CUSTODY_KEY} from './production-authority-v2.mjs';
import {administer} from './open-authority-administration.mjs';

const HISTORICAL_SITE_ID='813ee022-f4d9-4d8e-a974-86158583a39f';
const ROOT_PIN='e3a0a2945081823171841bde32a6df7fc505b6f0b3e6ab9b6c85ecc9f3d49bfc';
const ISSUER_ID='8d65f5a4057eedb76ac3db83e9217a374c0072adfa3986b4745e4b5b5bbb22e8';
const HISTORICAL_ORIGIN='https://wheelerhubbellpublishingstandingmark.netlify.app';
const RATIFICATION='public/authority/ratifications/open-acquisition-v1.1/root.json';
const PUBLIC_ROOT='public/authority/root.json';

function proveExistingCustody(c){
  demand(c&&typeof c.root_private_key==='string'&&typeof c.issuer_private_key==='string','EXISTING_CUSTODY_REQUIRED');
  const rootPublic=publicDer(c.root_private_key),issuerPublic=publicDer(c.issuer_private_key);
  demand(keyId(rootPublic)===ROOT_PIN&&keyId(issuerPublic)===ISSUER_ID,'EXISTING_CUSTODY_IDENTITY_MISMATCH');
  const nonce=randomHex();
  const rootProof=seal('WHP-EXISTING-CUSTODY-PROOF-v1',{nonce,role:'ROOT'},c.root_private_key);
  const issuerProof=seal('WHP-EXISTING-CUSTODY-PROOF-v1',{nonce,role:'ISSUER'},c.issuer_private_key);
  demand(openSeal(rootProof,'WHP-EXISTING-CUSTODY-PROOF-v1',rootPublic).nonce===nonce,'EXISTING_ROOT_SIGNING_ACCESS_FAILED');
  demand(openSeal(issuerProof,'WHP-EXISTING-CUSTODY-PROOF-v1',issuerPublic).nonce===nonce,'EXISTING_ISSUER_SIGNING_ACCESS_FAILED');
  return {root_pin:ROOT_PIN,issuer_key_id:ISSUER_ID,root_signing_access_verified:true,issuer_signing_access_verified:true};
}

async function immutableWrite(path,bytes){
  try{await writeFile(path,bytes,{flag:'wx'});}catch(e){if(e.code!=='EEXIST')throw e;demand(await readFile(path,'utf8')===bytes,'HISTORICAL_RECORD_CONFLICT');}
}

async function ensureCurrentOriginRatification(custody){
  const ratificationRaw=await readFile(RATIFICATION,'utf8'),ratification=parseStrict(ratificationRaw,2000000);
  const act=openSeal(ratification.authorization_act,'WHP-EXISTING-ROOT-RATIFICATION-v1.1',ratification.root_public_key);
  demand(ratification.root_pin===ROOT_PIN&&ratification.issuer_key_id===ISSUER_ID&&act.root_pin===ROOT_PIN&&act.issuer_key_id===ISSUER_ID,'RATIFICATION_IDENTITY_MISMATCH');
  if(ratification.canonical_origin===ORIGIN&&act.canonical_origin===ORIGIN)return {origin_migrated:false};
  demand(ratification.canonical_origin===HISTORICAL_ORIGIN&&act.canonical_origin===HISTORICAL_ORIGIN,'UNEXPECTED_RATIFICATION_ORIGIN');
  const currentRaw=await readFile(PUBLIC_ROOT,'utf8'),current=parseStrict(currentRaw,2000000);
  demand(current.root_pin===ROOT_PIN&&current.issuer_key_id===ISSUER_ID&&current.canonical_origin===HISTORICAL_ORIGIN,'UNEXPECTED_PUBLIC_AUTHORITY_ORIGIN');
  demand(keyId(publicDer(custody.root_private_key))===ROOT_PIN,'EXISTING_CUSTODY_IDENTITY_MISMATCH');
  await mkdir('public/authority/ratifications/open-acquisition-v1.1/history',{recursive:true});
  await mkdir('public/authority/history',{recursive:true});
  await immutableWrite('public/authority/ratifications/open-acquisition-v1.1/history/'+hash(ratification)+'.json',ratificationRaw);
  await immutableWrite('public/authority/history/'+hash(current)+'.json',currentRaw);
  await immutableWrite('public/authority/history/'+hash(current)+'.trust-bundle.json',canonical(current.trust_bundle)+'\n');
  const migratedAt=Math.floor(Date.now()/1000);
  const migratedPayload={...act,canonical_origin:ORIGIN,ratified_at:migratedAt,authorization:'Continue with your fixes.',authorization_context:'Wheeler Hubbell Publishing authorized continuing the production-target repair. This signature changes only the canonical Netlify production origin while preserving the existing WHP root, issuer, v1.1 profile, contract, verifier, authority scope and payment semantics.',origin_migration_from:HISTORICAL_ORIGIN,origin_migration_only:true,previous_ratification_sha256:hash(ratification)};
  const authorization_act=seal('WHP-EXISTING-ROOT-RATIFICATION-v1.1',migratedPayload,custody.root_private_key);
  const migratedRatification={...ratification,canonical_origin:ORIGIN,authorization_act};
  const {current_production_authority_replaced,...base}=migratedRatification;
  const migratedPublic={...base,trust_bundle:current.trust_bundle,production_activation_requires:'Matching existing-root authorization, runtime configuration and successful open-acquisition TEST gate.',production_completion_requires:'After deployment, the unchanged LIVE release gate must verify the real paid A-to-B chain.',historical_authority_url:ORIGIN+'/authority/history/'+act.previous_public_authority_sha256+'.json',authorization_ratification_url:ORIGIN+'/authority/ratifications/open-acquisition-v1.1/root.json'};
  await writeFile(RATIFICATION,canonical(migratedRatification)+'\n');
  await writeFile(PUBLIC_ROOT,canonical(migratedPublic)+'\n');
  return {origin_migrated:true,origin_from:HISTORICAL_ORIGIN,origin_to:ORIGIN,previous_ratification_sha256:hash(ratification),new_ratification_sha256:hash(migratedRatification)};
}

export async function readExistingCustody(){
  const current=await target();
  const present=await variable(current,CUSTODY_KEY);
  if(present){
    demand(present.values?.length===1&&present.values[0].context==='dev','EXISTING_DEV_CUSTODY_REQUIRED');
    const custody=parseStrict(value(present,'dev'),1048576),proof=proveExistingCustody(custody);
    return {site:current,custody,source:'current-site',...proof};
  }
  const historical=await api('/sites/'+HISTORICAL_SITE_ID);
  demand(historical?.id===HISTORICAL_SITE_ID&&historical?.account_id,'HISTORICAL_CUSTODY_SITE_REQUIRED');
  const record=await variable(historical,CUSTODY_KEY);
  demand(record?.values?.length===1&&record.values[0].context==='dev','HISTORICAL_DEV_CUSTODY_REQUIRED');
  const custody=parseStrict(value(record,'dev'),1048576),proof=proveExistingCustody(custody);
  return {site:current,custody,source:'historical-site',source_site_id:HISTORICAL_SITE_ID,...proof};
}

export async function syncV11Authority(directory='artifacts/authority-prepared'){
  const existing=await readExistingCustody();
  const origin=await ensureCurrentOriginRatification(existing.custody);
  await rm(directory,{recursive:true,force:true});
  const administration=await administer('sync',directory,existing.custody);
  await mkdir('public/authority/history',{recursive:true});
  await copyFile(directory+'/root.json','public/authority/root.json');
  await copyFile(directory+'/trust-bundle.json','public/authority/trust-bundle.json');
  try{for(const name of await readdir(directory+'/history'))await copyFile(directory+'/history/'+name,'public/authority/history/'+name);}catch(e){if(e.code!=='ENOENT')throw e;}
  return {custody_source:existing.source,root_pin:existing.root_pin,issuer_key_id:existing.issuer_key_id,...origin,status_sequence:administration.status_sequence,status_renewed:administration.status_renewed,production_configuration_changed:administration.production_configuration_changed,generated_new_keys:false,root_rotated:false,private_custody_migrated:false,payment_executed:false};
}
