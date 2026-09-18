// Administrative fresh-key ceremony. This module is never imported by a production handler.
import {generateKeyPairSync} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {canonical,parseStrict,demand,hash,hashBytes,publicDer,keyId,seal,openSeal,randomHex,clone} from '../src/canonical.mjs';
import {validateTrust} from '../src/authority.mjs';
import {evaluate} from '../src/evaluator.mjs';
import {AUTHORIZATION,establish,verifyAuthority,SCOPE,JURISDICTION,PROFILE_COMMITMENT} from './authority-core.mjs';
import {ORIGIN,COMMITMENTS,variable,value,put,createVariable,verifySourceCommitments} from './netlify-production-target.mjs';
export const CEREMONY='WHP-FRESH-PRODUCTION-2026-09-15T22:45:12Z';
export const CUSTODY_KEY='WHP_AUTHORITY_CUSTODY_V2';
export const STATUS_KEY='WHP_AUTHORITY_STATUS_V2';
const RESERVATION_KEY='WHP_FRESH_KEYS_RESERVED_V2';
export const ROOT_FILE='public/authority/root.json';
const SOURCE_FILE='public/authority/source-admission.json';
const pem=()=>generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'}).toString();
export async function readPublic(){return parseStrict(await readFile(ROOT_FILE,'utf8'),1048576);}
export function proveCustody(c){
 demand(c?.ceremony_id===CEREMONY&&Number.isSafeInteger(c.created_at),'FRESH_CUSTODY_RECORD_INVALID');
 const pairs=[['root_private_key','root_pin'],['issuer_private_key','issuer_key_id'],['source_private_key','source_key_id']];
 for(const [secret,id] of pairs){const pub=publicDer(c[secret]);demand(keyId(pub)===c[id],'STORED_KEY_FINGERPRINT_MISMATCH');const nonce=randomHex();const proof=seal('WHP-CUSTODY-PROOF-v1',{ceremony_id:CEREMONY,nonce},c[secret]);demand(openSeal(proof,'WHP-CUSTODY-PROOF-v1',pub).nonce===nonce,'STORED_SIGNING_ACCESS_FAILED');}
 demand(new Set(pairs.map(([,id])=>c[id])).size===3&&c.root_pin!==c.previous_root_pin,'FRESH_KEY_SEPARATION_FAILED');
 return {root_pin:c.root_pin,issuer_key_id:c.issuer_key_id,source_key_id:c.source_key_id,root_signing_access_verified:true,issuer_signing_access_verified:true,source_signing_access_verified:true};
}
export function assertAuthorityContinuity(pub,c){
 const proof=proveCustody(c),b=pub?.trust_bundle;
 demand(pub?.root_pin===proof.root_pin&&pub?.issuer_key_id===proof.issuer_key_id,'UNRELATED_PUBLIC_AUTHORITY_CHANGE');
 demand(b?.root_public_key&&keyId(b.root_public_key)===proof.root_pin,'UNRELATED_PUBLIC_AUTHORITY_CHANGE');
 const issuer=b?.certificates?.some(e=>e?.payload?.roles?.includes('ISSUER')&&keyId(e.payload.public_key)===proof.issuer_key_id);
 const source=b?.certificates?.some(e=>e?.payload?.roles?.includes('SOURCE')&&keyId(e.payload.public_key)===proof.source_key_id);
 demand(issuer&&source,'UNRELATED_PUBLIC_AUTHORITY_CHANGE');return proof;
}
export async function readCustody(site){
 const record=await variable(site,CUSTODY_KEY);demand(record&&record.values?.length===1&&record.values[0].context==='dev','FRESH_ADMIN_CUSTODY_REQUIRED');
 const c=parseStrict(value(record,'dev'),1048576);proveCustody(c);return c;
}
export async function getOrEstablishCustody(site,published){
 await verifySourceCommitments();
 const existing=await variable(site,CUSTODY_KEY);if(existing)return readCustody(site);
 // Reserve this named ceremony before generation. A storage interruption cannot silently create a second set.
 demand(!await variable(site,RESERVATION_KEY),'FRESH_CEREMONY_STORAGE_INTERRUPTED');
 await createVariable(site,RESERVATION_KEY,canonical({ceremony_id:CEREMONY,generation_reserved:true}),'dev');
 const reserved=await variable(site,RESERVATION_KEY);demand(reserved?.values?.length===1&&reserved.values[0].context==='dev'&&parseStrict(value(reserved,'dev')).ceremony_id===CEREMONY,'CEREMONY_RESERVATION_READBACK_FAILED');
 const c={ceremony_id:CEREMONY,created_at:Math.floor(Date.now()/1000),source_commit:process.env.GITHUB_SHA??null,previous_root_pin:published.root_pin,previous_public_authority_sha256:hash(published),previous_public_authority_bytes_sha256:hashBytes(await readFile(ROOT_FILE)),root_private_key:pem(),issuer_private_key:pem(),source_private_key:pem()};
 c.root_pin=keyId(publicDer(c.root_private_key));c.issuer_key_id=keyId(publicDer(c.issuer_private_key));c.source_key_id=keyId(publicDer(c.source_private_key));
 proveCustody(c);
 // Only private material and small ceremony metadata live in this isolated durable record, not growing public history.
 await createVariable(site,CUSTODY_KEY,canonical(c),'dev');
 const stored=await readCustody(site);demand(hash(stored)===hash(c),'FRESH_CUSTODY_READBACK_FAILED');return stored;
}
export function makeFreshAuthority(c){
 const a=establish(c,AUTHORIZATION,c.created_at),b=a.bundle;
 b.certificates.push(seal('WHP-AUTHORITY-CERTIFICATE-v1',{public_key:publicDer(c.source_private_key),subject:'Wheeler Hubbell Publishing — attestations of WHP-controlled protocol identity records only',roles:['SOURCE'],scopes:[SCOPE],jurisdictions:[JURISDICTION],operations:['INFORM'],profile_hash:COMMITMENTS.profile,valid_from:c.created_at-30,valid_until:c.created_at+31536000},c.root_private_key));
 b.status_snapshot=seal('WHP-TRUST-STATUS-v1',{...b.status_snapshot.payload,certificates_hash:hash(b.certificates)},c.root_private_key);
 a.act=seal('WHP-FIRST-PUBLIC-RATIFICATION-v1',{...a.act.payload,authorization:'I authorize establishing fresh root and issuer signing keys for this production version and replacing the current public authority material and runtime configuration with one coherent, matching set.',authorization_received_at:'2026-09-15T22:45:12Z',ceremony_id:CEREMONY,signing_identity_changed:true,continues_previous_trust_identity:false,previous_public_authority_sha256:c.previous_public_authority_sha256,trust_bundle_hash:hash(b),limitation:'Protocol-scoped structural assessment and specifically signed WHP-controlled protocol identity records. The SOURCE key is separate from the issuer, admits INFORM only, and remains in administrative custody. No TRANSITION authority, external factual or legal authority, payment, or Mark issuance is established by this ceremony.'},c.root_private_key);
 return a;
}
export function makeSourceRecord(c){
 const payload={id:'urn:whp:standing:controlled-production-contract',version:'1',content:{kind:'WHP-CONTROLLED-PROTOCOL-IDENTITY-v1',issuer:'Wheeler Hubbell Publishing',authorized_production_origin:ORIGIN,profile_sha256:COMMITMENTS.profile,contract_sha256:COMMITMENTS.contract,verifier_sha256:COMMITMENTS.verifier,meaning:'This records WHP controlled protocol commitments, not service readiness or the truth of external claims.'},locator:ORIGIN+'/authority/source-admission.json',epistemic_status:'REPORT',qualifiers:['WHP-controlled protocol identity only; no external factual or legal authority.','No service-readiness or payment observation is asserted.'],unknowns:[],operations:['INFORM'],scope:SCOPE,jurisdiction:JURISDICTION,valid_from:c.created_at-30,valid_until:c.created_at+31536000,status:'ACTIVE',prior_hash:null};
 return seal('WHP-SOURCE-ATTESTATION-v1',payload,c.source_private_key);
}
export function checkAdmission(c,b,node,at){
 const buyer=generateKeyPairSync('ed25519').privateKey;
 const s={version:'WHP-STANDING-SUBMISSION-v1',client_reference:'whp_bounded_source_admission',buyer_key:publicDer(buyer),profile:PROFILE_COMMITMENT,object:{id:node.payload.id,version:node.payload.version,root:hash(node.payload)},bounds:{scope:SCOPE,jurisdiction:JURISDICTION,valid_from:at,valid_until:Math.min(at+3600,node.payload.valid_until,b.profile_authorization.payload.valid_until)},requested_operation:'INFORM',nodes:[node],transitions:[]};
 const d=evaluate(s,b,c.root_pin,at);demand(d.outcome==='ESTABLISHED'&&d.components.RELATION==='NOT_ASSESSED'&&d.components.PASSAGE==='NOT_ASSESSED','BOUNDED_SOURCE_ADMISSION_FAILED');
 const counterfeit=clone(s);counterfeit.nodes=[seal('WHP-SOURCE-ATTESTATION-v1',node.payload,buyer)];
 demand(evaluate(counterfeit,b,c.root_pin,at).outcome==='NOT_ESTABLISHED','BUYER_BECAME_SOURCE_AUTHORITY');
 return {outcome:d.outcome,source_key_id:c.source_key_id,source_record_sha256:hash(node),permitted_operations:d.permitted_operations,source_role_separate_from_issuer:true,buyer_as_source_rejected:true,transitions:0,relation:'NOT_ASSESSED',passage:'NOT_ASSESSED',payment_executed:false,live_mark_issued:false};
}
export async function resumeStatus(site,c,b){
 const row=await variable(site,STATUS_KEY);if(!row)return b;
 demand(row.values?.length===1&&row.values[0].context==='dev','STATUS_CUSTODY_CONTEXT_INVALID');
 const saved=parseStrict(value(row,'dev'));demand(saved.ceremony_id===CEREMONY&&saved.root_pin===c.root_pin,'STATUS_CUSTODY_IDENTITY_MISMATCH');
 const p=openSeal(saved.snapshot,'WHP-TRUST-STATUS-v1',b.root_public_key),prior=b.status_snapshot.payload;
 if(p.sequence<prior.sequence)return b;
 if(p.sequence===prior.sequence){demand(hash(saved.snapshot)===hash(b.status_snapshot),'STATUS_SEQUENCE_CONFLICT');return b;}
 demand(p.sequence===prior.sequence+1&&p.previous_hash===hash(b.status_snapshot),'STATUS_CHAIN_CONFLICT');
 demand(p.profile_authorization_hash===hash(b.profile_authorization)&&p.certificates_hash===hash(b.certificates)&&p.revocations_hash===hash(b.revocations),'STATUS_PENDING_MANIFEST_CONFLICT');
 b.status_snapshot=saved.snapshot;return b;
}
export function renewStatus(c,b,now){
 const prior=b.status_snapshot;validateTrust(b,c.root_pin,Math.max(prior.payload.valid_from,Math.min(now,prior.payload.valid_until-1)));
 const until=Math.min(now+86400,b.profile_authorization.payload.valid_until,...b.certificates.map(e=>e.payload.valid_until));
 demand(until>now+3600,'AUTHORITY_RENEWAL_REQUIRED');
 if(prior.payload.valid_until<now+64800)b.status_snapshot=seal('WHP-TRUST-STATUS-v1',{...prior.payload,sequence:prior.payload.sequence+1,previous_hash:hash(prior),profile_authorization_hash:hash(b.profile_authorization),certificates_hash:hash(b.certificates),revocations_hash:hash(b.revocations),valid_from:now-30,valid_until:until},c.root_private_key);
 validateTrust(b,c.root_pin,now);return b;
}
export async function persistStatus(site,c,b){
 const state={ceremony_id:CEREMONY,root_pin:c.root_pin,snapshot:b.status_snapshot};await put(site,STATUS_KEY,canonical(state),'dev');
 const back=await variable(site,STATUS_KEY);demand(back?.values?.length===1&&back.values[0].context==='dev'&&hash(parseStrict(value(back,'dev')))===hash(state),'STATUS_CUSTODY_READBACK_FAILED');
}
export async function installAuthority(site,c,b){
 const now=Math.floor(Date.now()/1000);verifyAuthority(b,c.root_pin,c.issuer_private_key,now);
 for(const [k,v] of Object.entries({WHP_ORIGIN:ORIGIN,WHP_ROOT_PIN:c.root_pin,WHP_TRUST_BUNDLE_JSON:canonical(b),WHP_ISSUER_PRIVATE_KEY:c.issuer_private_key}))await put(site,k,v,'production');
 for(const [k,v] of Object.entries({WHP_ORIGIN:ORIGIN,WHP_ROOT_PIN:c.root_pin,WHP_TRUST_BUNDLE_JSON:canonical(b)}))demand(value(await variable(site,k))===v,'AUTHORITY_CONFIGURATION_READBACK_FAILED');
 const issuer=await variable(site,'WHP_ISSUER_PRIVATE_KEY');demand(issuer?.values?.length===1&&issuer.values[0].context==='production'&&keyId(publicDer(value(issuer)))===c.issuer_key_id,'ISSUER_RUNTIME_CUSTODY_MISMATCH');
 const stored=await readCustody(site);demand(stored.root_pin===c.root_pin&&stored.issuer_key_id===c.issuer_key_id,'ADMIN_RUNTIME_CUSTODY_MISMATCH');
 return {root_pin:c.root_pin,issuer_key_id:c.issuer_key_id,trust_bundle_sha256:hash(b),runtime_configuration_readback_verified:true,root_and_source_material_excluded_from_production_context:true,deployed_runtime_observed:false};
}
export async function writePublic(c,a,node,previous){
 await mkdir('public/authority/history',{recursive:true});
 if(previous.root_pin!==c.root_pin){
  demand(hash(previous)===c.previous_public_authority_sha256,'PUBLIC_AUTHORITY_CHANGED_DURING_CEREMONY');
  const bytes=await readFile(ROOT_FILE);demand(hashBytes(bytes)===c.previous_public_authority_bytes_sha256,'HISTORICAL_PUBLIC_BYTES_CHANGED');
  const path='public/authority/history/'+c.previous_public_authority_sha256+'.json';
  try{await writeFile(path,bytes,{flag:'wx'});}catch(e){if(e.code!=='EEXIST')throw e;demand(hashBytes(await readFile(path))===hashBytes(bytes),'HISTORICAL_RECORD_CONFLICT');}
 }
 const pub={version:'WHP-PUBLIC-AUTHORITY-v1',ceremony_id:CEREMONY,canonical_origin:ORIGIN,root_pin:c.root_pin,root_public_key:a.bundle.root_public_key,issuer_key_id:c.issuer_key_id,source_key_id:c.source_key_id,profile:PROFILE_COMMITMENT,contract_sha256:COMMITMENTS.contract,verifier_sha256:COMMITMENTS.verifier,authorization_act:a.act,trust_bundle:a.bundle,source_admission_url:ORIGIN+'/authority/source-admission.json',previous_public_authority_sha256:c.previous_public_authority_sha256,historical_authority_url:ORIGIN+'/authority/history/'+c.previous_public_authority_sha256+'.json',custody:'Private custody was stored and read back before these public counterparts were written. Root and source keys are administrative-context only. Production receives the issuer key.',pinning:'This is a new root identity, not continuation of the previous trust identity. Admit its fingerprint through an independently authenticated WHP origin or trusted issuer record.'};
 await writeFile(ROOT_FILE,canonical(pub)+'\n');await writeFile('public/authority/trust-bundle.json',canonical(a.bundle)+'\n');
 await writeFile(SOURCE_FILE,canonical({version:'WHP-BOUNDED-SOURCE-ADMISSION-v1',root_pin:c.root_pin,source_key_id:c.source_key_id,certificate:a.bundle.certificates.find(e=>keyId(e.payload.public_key)===c.source_key_id),signed_record:node,permitted_operations:['INFORM'],transition_authority_granted:false,buyer_authority_granted:false,limitation:'Only this actual signed WHP-controlled protocol record is supplied. A buyer must authenticate separately and cannot change the source record or infer external authority.'})+'\n');return pub;
}
export async function readSourceRecord(){return parseStrict(await readFile(SOURCE_FILE,'utf8'),1048576).signed_record;}
