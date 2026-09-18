// Explicit v1.1 ratification with the existing root and issuer. No key generation,
// network calls, runtime configuration, deployment, source grants or payments.
// Private custody enters through stdin and is never written to the output files.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {canonical,parseStrict,hash,hashBytes,keyId,publicDer,seal,openSeal,demand} from '../src/canonical.mjs';
import {PROFILE_HASH,PROFILE_ID,PROFILE_VERSION,OPERATIONS} from '../src/profile.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {validateTrust,issuerAuthority,authorize} from '../src/authority.mjs';
import {validateTrust as validatePreviousTrust} from '../legacy/v1/src/authority.mjs';

const APPROVAL='Okay, I approve. Can I- can you do it?';
const ORIGIN='https://wheelerhubbellpublishingstandingmark.netlify.app';
const SOURCE_COMMIT='faf63398f4166d251304bce7a63c3a06eabb9f23';
const SOURCE_TREE='1045e8f9fdda99d901b85dfb8fc353f92cad5130';
const DIRECTORY='public/authority/ratifications/open-acquisition-v1.1';

try{
  let raw='';for await(const part of process.stdin){raw+=part;demand(Buffer.byteLength(raw)<=65536,'RATIFICATION_INPUT_TOO_LARGE');}
  const input=parseStrict(raw,65536);raw='';
  demand(input.authorization===APPROVAL,'EXPLICIT_VERSION_APPROVAL_REQUIRED');
  const {custody:c,previous}=input,at=Math.floor(Date.now()/1000);
  const rootPub=publicDer(c.root_private_key),issuerPub=publicDer(c.issuer_private_key);
  const pin=keyId(rootPub),issuerId=keyId(issuerPub);
  demand(previous.canonical_origin===ORIGIN&&previous.root_pin===pin&&previous.root_public_key===rootPub&&c.root_pin===pin,'EXISTING_ROOT_MISMATCH');
  demand(previous.issuer_key_id===issuerId&&c.issuer_key_id===issuerId,'EXISTING_ISSUER_MISMATCH');
  const old=previous.trust_bundle;
  validatePreviousTrust(old,pin,Math.max(old.status_snapshot.payload.valid_from,Math.min(at,old.status_snapshot.payload.valid_until-1)));
  const oldIssuer=old.certificates.find(e=>keyId(e.payload.public_key)===issuerId)?.payload;
  demand(oldIssuer&&oldIssuer.roles.includes('ISSUER')&&oldIssuer.valid_from<=at&&at<oldIssuer.valid_until,'EXISTING_ISSUER_EXPIRED');
  demand(!old.revocations.map(e=>openSeal(e,'WHP-KEY-REVOCATION-v1',rootPub)).some(r=>[pin,issuerId].includes(r.key_id)&&r.effective_at<=at),'EXISTING_AUTHORITY_REVOKED');
  const git=(...args)=>execFileSync('git',args,{encoding:'utf8'}).trim();
  demand(git('rev-parse',SOURCE_COMMIT+'^{tree}')===SOURCE_TREE,'APPROVED_SOURCE_TREE_MISMATCH');
  for(const path of ['profiles/structured-passage-1.1.0.json','public/contract.json','public/verifier-manifest.json','verify/verify_mark.py']){
    demand(hashBytes(await readFile(path))===hashBytes(execFileSync('git',['show',SOURCE_COMMIT+':'+path])),'APPROVED_SOURCE_CHANGED');
  }
  demand(hashBytes(await readFile('verify/verify_mark.py'))===VERIFIER_HASH,'VERIFIER_COMMITMENT_MISMATCH');
  const from=at-30,until=Math.min(old.profile_authorization.payload.valid_until,oldIssuer.valid_until);
  demand(until>at+86400,'EXISTING_AUTHORITY_RENEWAL_REQUIRED');
  const certificate=seal('WHP-AUTHORITY-CERTIFICATE-v1',{
    public_key:issuerPub,subject:'Wheeler Hubbell Publishing — WHP Standing v1.1 issuer, registry and discovery',
    roles:['ISSUER','REGISTRY','DISCOVERY'],scopes:['whp-standing-structured-passage','github-repository:*'],
    jurisdictions:['protocol-structural-assessment-only','namespace-control'],operations:OPERATIONS,
    profile_hash:PROFILE_HASH,valid_from:from,valid_until:until
  },c.root_private_key);
  const bundle={root_public_key:rootPub,profile_authorization:seal('WHP-PROFILE-AUTHORIZATION-v1',{
    profile_hash:PROFILE_HASH,contract_hash:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,ratified:true,
    issuer:'Wheeler Hubbell Publishing',environment:'LIVE',valid_from:from,valid_until:until
  },c.root_private_key),certificates:[certificate],revocations:old.revocations};
  bundle.status_snapshot=seal('WHP-TRUST-STATUS-v1',{
    sequence:0,previous_hash:null,profile_authorization_hash:hash(bundle.profile_authorization),
    certificates_hash:hash(bundle.certificates),revocations_hash:hash(bundle.revocations),valid_from:from,valid_until:at+86400
  },c.root_private_key);
  const act=seal('WHP-EXISTING-ROOT-RATIFICATION-v1.1',{
    authorization:APPROVAL,authorization_context:'The user approved using the existing WHP signing key to approve the exact new version rules explained in this conversation.',
    ratified_at:at,issuer:'Wheeler Hubbell Publishing',canonical_origin:ORIGIN,root_pin:pin,root_public_key:rootPub,
    issuer_key_id:issuerId,issuer_public_key:issuerPub,profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH},
    contract_sha256:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,trust_bundle_sha256:hash(bundle),
    approved_source_commit:SOURCE_COMMIT,approved_source_tree:SOURCE_TREE,previous_public_authority_sha256:hash(previous),
    previous_status_snapshot_sha256:hash(old.status_snapshot),status_epoch:'New profile-bound epoch; historical v1 status and result bytes remain unchanged.',
    existing_root_preserved:true,existing_issuer_preserved:true,source_or_transition_authority_granted:false,
    limitation:'Authorizes the exact v1.1 evaluator and bounded GitHub namespace observation. Each requester must supply its own valid source and transformation authority. This act does not assert deployment, payment, Mark issuance or LIVE chain completion.'
  },c.root_private_key);
  const trust=validateTrust(bundle,pin,at);
  issuerAuthority(issuerId,'https://github.com/independent-controller/records','namespace-control',trust);
  issuerAuthority(issuerId,'whp-standing-structured-passage','protocol-structural-assessment-only',trust);
  const challenge=seal('WHP-ISSUER-CUSTODY-PROOF-v1.1',{root_pin:pin,ratification_sha256:hash(act),at},c.issuer_private_key);
  authorize(challenge,'WHP-ISSUER-CUSTODY-PROOF-v1.1','REGISTRY',{scope:'https://github.com/independent-controller/records',jurisdiction:'namespace-control',operations:['INFORM']},trust);
  openSeal(act,'WHP-EXISTING-ROOT-RATIFICATION-v1.1',rootPub);
  const denied=(fn)=>{try{fn();}catch{return true;}return false;};
  const altered=structuredClone(bundle);altered.profile_authorization.payload.profile_hash='0'.repeat(64);
  demand(denied(()=>validateTrust(altered,pin,at)),'MODIFIED_RULES_NOT_REJECTED');
  demand(denied(()=>issuerAuthority(issuerId,'all-objects','external-legal-authority',trust)),'UNBOUNDED_AUTHORITY_NOT_REJECTED');
  const published={version:'WHP-PUBLIC-AUTHORITY-v1.1',canonical_origin:ORIGIN,root_pin:pin,root_public_key:rootPub,issuer_key_id:issuerId,
    profile:act.payload.profile,contract_sha256:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,authorization_act:act,trust_bundle:bundle,
    current_production_authority_replaced:false,production_activation_requires:'Matching runtime configuration and successful LIVE release gate.'};
  const proof={checked_at:new Date().toISOString(),state:'EXISTING_ROOT_RATIFICATION_VERIFIED',root_pin:pin,issuer_key_id:issuerId,
    profile_sha256:PROFILE_HASH,contract_sha256:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,ratification_sha256:hash(act),trust_bundle_sha256:hash(bundle),
    existing_root_preserved:true,existing_issuer_preserved:true,root_signature_verified:true,issuer_custody_proof:challenge,
    source_whitelist_created:false,modified_rules_rejected:true,unbounded_authority_rejected:true,
    status_valid_until:bundle.status_snapshot.payload.valid_until,profile_authorization_valid_until:until,
    production_configuration_changed:false,deployed:false,payment_executed:false,live_mark_issued:false,live_chain_completed:false};
  for(const value of [published,bundle,proof])demand(!canonical(value).includes('PRIVATE KEY'),'PRIVATE_MATERIAL_IN_PUBLIC_OUTPUT');
  await mkdir(DIRECTORY,{recursive:true});await mkdir('evidence/open-acquisition',{recursive:true});
  for(const [path,value] of [[DIRECTORY+'/root.json',published],[DIRECTORY+'/trust-bundle.json',bundle],['evidence/open-acquisition/existing-root-ratification.json',proof]])await writeFile(path,canonical(value)+'\n',{flag:'wx'});
  console.log(JSON.stringify({signed:true,verified:true,root_pin:pin,issuer_key_id:issuerId,profile_sha256:PROFILE_HASH,contract_sha256:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,public_authority:DIRECTORY+'/root.json',deployed:false}));
}catch(e){console.error(JSON.stringify({signed:false,error:e.code??'RATIFICATION_FAILED'}));process.exitCode=1;}
