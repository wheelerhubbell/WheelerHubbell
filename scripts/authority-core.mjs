// Production authority uses the same closed contracts and primitives as every Mark.
// No independent signing implementation and no file/network/key-custody side effects.
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {seal,hash,keyId,publicDer,demand,clone,openSeal} from '../src/canonical.mjs';
import {validateTrust,issuerAuthority,authorize} from '../src/authority.mjs';
import {PROFILE_HASH,PROFILE_ID,PROFILE_VERSION,OPERATIONS} from '../src/profile.mjs';

export const AUTHORIZATION='I authorize establishment of Wheeler Hubbell Publishing’s production cryptographic root and issuer authority for WHP Standing v1.';
export const SCOPE='whp-standing-structured-passage';
export const JURISDICTION='protocol-structural-assessment-only';
export const ORIGIN='https://wheelerhubbellpublishingstandingmark.netlify.app';
export const PROFILE_COMMITMENT={id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH};

export function establish(custody,authorization,at){
  demand(authorization===AUTHORIZATION,'EXPLICIT_AUTHORIZATION_REQUIRED');
  demand(Number.isSafeInteger(at)&&at>0,'AUTHORITY_TIME_REQUIRED');
  const root=custody.root_private_key,issuer=custody.issuer_private_key;
  const rootPub=publicDer(root),issuerPub=publicDer(issuer),pin=keyId(rootPub),issuerId=keyId(issuerPub);
  const from=at-30,until=at+31536000;
  const certificate=seal('WHP-AUTHORITY-CERTIFICATE-v1',{
    public_key:issuerPub,subject:'Wheeler Hubbell Publishing — WHP Standing v1 issuer and registry',
    roles:['ISSUER','REGISTRY','DISCOVERY'],scopes:[SCOPE],jurisdictions:[JURISDICTION],operations:OPERATIONS,
    profile_hash:PROFILE_HASH,valid_from:from,valid_until:until
  },root);
  const bundle={root_public_key:rootPub,profile_authorization:seal('WHP-PROFILE-AUTHORIZATION-v1',{
    profile_hash:PROFILE_HASH,contract_hash:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,ratified:true,issuer:'Wheeler Hubbell Publishing',environment:'LIVE',valid_from:from,valid_until:until
  },root),certificates:[certificate],revocations:[]};
  bundle.status_snapshot=seal('WHP-TRUST-STATUS-v1',{
    sequence:0,previous_hash:null,profile_authorization_hash:hash(bundle.profile_authorization),certificates_hash:hash(bundle.certificates),revocations_hash:hash(bundle.revocations),valid_from:from,valid_until:at+86400
  },root);
  const act=seal('WHP-FIRST-PUBLIC-RATIFICATION-v1',{
    authorization:'Wheeler Hubbell Publishing authorizes this production WHP Standing v1 machine.',authorization_received_at:'2026-09-15T21:12:14Z',ratified_at:at,
    issuer:'Wheeler Hubbell Publishing',canonical_origin:ORIGIN,root_pin:pin,root_public_key:rootPub,
    issuer_key_id:issuerId,issuer_public_key:issuerPub,profile:PROFILE_COMMITMENT,
    contract_hash:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,trust_bundle_hash:hash(bundle),scope:SCOPE,jurisdiction:JURISDICTION,
    limitation:'Protocol-scoped structural assessment. No external legal or domain authority is conferred. No source or transition authority is manufactured. No payment or Mark issuance occurs in this ceremony.'
  },root);
  verifyAuthority(bundle,pin,issuer,at);
  return {bundle,act,root_pin:pin,issuer_key_id:issuerId};
}

export function verifyAuthority(bundle,pin,issuer,at){
  const trust=validateTrust(bundle,pin,at),kid=keyId(publicDer(issuer));
  demand(trust.profile.environment==='LIVE'&&trust.profile.issuer==='Wheeler Hubbell Publishing','PRODUCTION_AUTHORITY_IDENTITY_REQUIRED');
  const cert=issuerAuthority(kid,SCOPE,JURISDICTION,trust);
  demand(cert.roles.includes('REGISTRY')&&cert.roles.includes('DISCOVERY'),'REGISTRY_AND_DISCOVERY_ROLES_REQUIRED');
  const challenge=seal('WHP-REGISTRY-CUSTODY-PROOF-v1',{root_pin:pin,at},issuer);
  authorize(challenge,'WHP-REGISTRY-CUSTODY-PROOF-v1','REGISTRY',{scope:SCOPE,jurisdiction:JURISDICTION,operations:['INFORM']},trust);
  demand(openSeal(challenge,'WHP-REGISTRY-CUSTODY-PROOF-v1',cert.public_key).root_pin===pin,'ISSUER_CUSTODY_PROOF_FAILED');
  return {root_pin_consistent:true,issuer_certificate_verified:true,issuer_private_key_matches_certificate:true,issuer_registry_and_discovery_roles_verified:true,scope:SCOPE,jurisdiction:JURISDICTION,profile:PROFILE_COMMITMENT,trust_status_verified:true,challenge};
}

export function authorityNegativeProof(bundle,pin,issuer,at){
  const denied=(name,fn)=>{try{fn();}catch{return {name,rejected:true};}throw Error('NEGATIVE_NOT_REJECTED_'+name);};
  const out=[];
  out.push(denied('wrong institutional root pin',()=>validateTrust(bundle,'00'.repeat(32),at)));
  const relabel=clone(bundle);relabel.profile_authorization.payload.environment='TEST';
  out.push(denied('environment relabel without root signature',()=>validateTrust(relabel,pin,at)));
  const profile=clone(bundle);profile.profile_authorization.payload.profile_hash='00'.repeat(32);
  out.push(denied('profile commitment tampering',()=>validateTrust(profile,pin,at)));
  out.push(denied('expired trust status',()=>validateTrust(bundle,pin,bundle.status_snapshot.payload.valid_until)));
  const trust=validateTrust(bundle,pin,at),kid=keyId(publicDer(issuer));
  out.push(denied('unadmitted jurisdiction',()=>issuerAuthority(kid,SCOPE,'external-legal-authority',trust)));
  out.push(denied('unadmitted scope',()=>issuerAuthority(kid,'all-objects',JURISDICTION,trust)));
  return out;
}
