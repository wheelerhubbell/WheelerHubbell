import { demand, openSeal, keyId, keyObject, exact, timeWindow, array, text, hash, canonical } from './canonical.mjs';
import { PROFILE_HASH } from './profile.mjs';
import { CONTRACT_HASH, VERIFIER_HASH } from './protocol.mjs';

// Trust is supplied out of band. Embedded certificates never appoint their own root.
export function validateTrust(bundle, pinnedRoot, at) {
  demand(Buffer.byteLength(canonical(bundle))<=65536,'TRUST_BUNDLE_TOO_LARGE',503);
  exact(bundle,['root_public_key','profile_authorization','certificates','revocations','status_snapshot']);
  demand(keyId(bundle.root_public_key)===pinnedRoot,'UNTRUSTED_ROOT'); keyObject(bundle.root_public_key);
  const pa=openSeal(bundle.profile_authorization,'WHP-PROFILE-AUTHORIZATION-v1',bundle.root_public_key);
  exact(pa,['profile_hash','contract_hash','verifier_sha256','ratified','issuer','environment','valid_from','valid_until']);timeWindow(pa);
  demand(pa.profile_hash===PROFILE_HASH && pa.contract_hash===CONTRACT_HASH && pa.verifier_sha256===VERIFIER_HASH && pa.ratified===true && pa.valid_from<=at && at<pa.valid_until,'PROFILE_NOT_AUTHORIZED');
  demand(['TEST','LIVE'].includes(pa.environment),'ENVIRONMENT_INVALID');text(pa.issuer);
  array(bundle.certificates,128);array(bundle.revocations,128);
  const status=openSeal(bundle.status_snapshot,'WHP-TRUST-STATUS-v1',bundle.root_public_key);
  exact(status,['sequence','previous_hash','profile_authorization_hash','certificates_hash','revocations_hash','valid_from','valid_until']);timeWindow(status);
  demand(Number.isSafeInteger(status.sequence)&&status.sequence>=0&&status.valid_from<=at&&at<status.valid_until,'TRUST_STATUS_EXPIRED');
  demand(status.profile_authorization_hash===hash(bundle.profile_authorization)&&status.certificates_hash===hash(bundle.certificates)&&status.revocations_hash===hash(bundle.revocations),'TRUST_STATUS_MANIFEST_MISMATCH');
  const revocations=bundle.revocations.map(e=>openSeal(e,'WHP-KEY-REVOCATION-v1',bundle.root_public_key));
  for(const r of revocations) { exact(r,['key_id','effective_at','reason']);text(r.key_id);text(r.reason); demand(Number.isSafeInteger(r.effective_at),'REVOCATION_TIME_INVALID'); }
  const keys=new Map();
  for(const e of bundle.certificates) {
    const c=openSeal(e,'WHP-AUTHORITY-CERTIFICATE-v1',bundle.root_public_key);
    exact(c,['public_key','subject','roles','scopes','jurisdictions','operations','profile_hash','valid_from','valid_until']);
    keyObject(c.public_key);text(c.subject);timeWindow(c);
    for(const k of ['roles','scopes','jurisdictions','operations']) {array(c[k],64); c[k].forEach(x=>text(x));}
    demand(c.roles.every(x=>['SOURCE','TRANSITION','ISSUER','REGISTRY','DISCOVERY'].includes(x)), 'CERTIFICATE_ROLE_INVALID');
    demand(c.profile_hash===PROFILE_HASH,'CERTIFICATE_PROFILE_MISMATCH');
    const id=keyId(c.public_key);demand(!keys.has(id),'DUPLICATE_AUTHORITY'); keys.set(id,c);
  }
  return {keys,revocations,profile:pa,bundle,pinnedRoot,at};
}
export function authorize(e,type,role,context,trust) {
  const c=trust.keys.get(e.protected.key_id);demand(c,'UNKNOWN_AUTHORITY');
  const p=openSeal(e,type,c.public_key);
  demand(c.roles.includes(role),'ROLE_NOT_AUTHORIZED');
  demand(c.scopes.includes(context.scope) && c.jurisdictions.includes(context.jurisdiction),'AUTHORITY_OUT_OF_BOUNDS');
  demand(c.valid_from<=trust.at && trust.at<c.valid_until,'AUTHORITY_EXPIRED');
  demand(!trust.revocations.some(r=>r.key_id===e.protected.key_id && r.effective_at<=trust.at),'AUTHORITY_REVOKED');
  demand((context.operations??[]).every(o=>c.operations.includes(o)),'AUTHORITY_OPERATION_DENIED');
  return {payload:p,certificate:c};
}
export function issuerAuthority(key,scope,jurisdiction,trust) {
  const c=trust.keys.get(key);demand(c && c.roles.includes('ISSUER'),'ISSUING_AUTHORITY_MISSING',503);
  demand(c.scopes.includes(scope) && c.jurisdictions.includes(jurisdiction),'ISSUER_OUT_OF_BOUNDS',503);
  demand(c.valid_from<=trust.at && trust.at<c.valid_until && !trust.revocations.some(r=>r.key_id===key && r.effective_at<=trust.at),'ISSUING_AUTHORITY_INVALID',503);
  return c;
}

// Current-status evaluation is deliberately distinct from historical issuance proof.
export function liveAuthorityIntact(result,trust){
  const p=result.payload,s=p.submission;
  try{
    issuerAuthority(p.issuer_key_id,s.bounds.scope,s.bounds.jurisdiction,trust);
    for(const e of s.nodes)authorize(e,'WHP-SOURCE-ATTESTATION-v1','SOURCE',{...s.bounds,operations:e.payload.operations},trust);
    for(const e of s.transitions)authorize(e,'WHP-TRANSITION-WARRANT-v1','TRANSITION',{...s.bounds,operations:e.payload.operations},trust);
    return true;
  }catch{return false;}
}
