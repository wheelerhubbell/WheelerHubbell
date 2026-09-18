// Fixture for the explicit v1 durable-row migration gate.
import {CONTRACT_HASH,VERIFIER_HASH} from '../../legacy/v1/src/protocol.mjs';
import {generateKeyPairSync} from 'node:crypto';
import {publicDer,keyId,seal,hash,canonical,clone,randomHex,encode} from '../../legacy/v1/src/canonical.mjs';
import {profile,PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from '../../legacy/v1/src/profile.mjs';
export const NOW=Math.floor(Date.parse('2026-09-15T08:48:10Z')/1000);
const keys=()=>generateKeyPairSync('ed25519');
export function fixture({at=NOW}={}){
  const root=keys(),issuer=keys(),source=keys(),transition=keys(),buyer=keys();
  const scope='submitted-example-only',jurisdiction='test-fixture-not-external-authority';
  const bounds={scope,jurisdiction,valid_from:at-100,valid_until:at+3600};
  const rootPub=publicDer(root.privateKey),rootPin=keyId(rootPub);
  const cert=(k,subject,roles)=>seal('WHP-AUTHORITY-CERTIFICATE-v1',{public_key:publicDer(k.privateKey),subject,roles,scopes:[scope],jurisdictions:[jurisdiction],operations:['INFORM','RECOMMEND','EXECUTE'],profile_hash:PROFILE_HASH,valid_from:at-1000,valid_until:at+604800},root.privateKey);
  const trustBundle={root_public_key:rootPub,profile_authorization:seal('WHP-PROFILE-AUTHORIZATION-v1',{
    profile_hash:PROFILE_HASH,contract_hash:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,ratified:true,issuer:'WHP Standing test issuer — not an institutional issuance',environment:'TEST',valid_from:at-1000,valid_until:at+604800},root.privateKey),
    certificates:[cert(issuer,'test-issuer',['ISSUER','REGISTRY','DISCOVERY']),cert(source,'test-source-attestor',['SOURCE']),cert(transition,'test-transition-authority',['TRANSITION'])],revocations:[]};
  trustBundle.status_snapshot=seal('WHP-TRUST-STATUS-v1',{sequence:0,previous_hash:null,profile_authorization_hash:hash(trustBundle.profile_authorization),certificates_hash:hash(trustBundle.certificates),revocations_hash:hash(trustBundle.revocations),valid_from:at-1000,valid_until:at+604800},root.privateKey);
  const leaf={id:'sample-observation',version:'1',content:{statement:'Three items are present in this submitted fixture.',count:3},locator:'urn:whp:test:source-1',epistemic_status:'REPORT',
    qualifiers:['Only this submitted fixture.','No external-world truth claim.'],unknowns:[{id:'external-validity',description:'No outside-world evidence is supplied.',blocks:['EXECUTE']}],operations:['INFORM','RECOMMEND'],
    ...bounds,valid_from:at-500,valid_until:at+7200,status:'ACTIVE',prior_hash:null};
  const target={...clone(leaf),id:'preserved-representation',locator:'urn:whp:test:representation-1'};
  const att=n=>seal('WHP-SOURCE-ATTESTATION-v1',n,source.privateKey);
  const edge={from:[hash(leaf)],to:hash(target),transform:'COPY',operations:['INFORM','RECOMMEND'],...bounds,valid_from:at-500,valid_until:at+7200,
    warrant:{statement:'Exact COPY of this source for INFORM or RECOMMEND only; all qualifiers and unknowns retained.',evidence_hashes:[hash(leaf)]}};
  const submission={version:'WHP-STANDING-SUBMISSION-v1',client_reference:'test-'+randomHex(16),buyer_key:publicDer(buyer.privateKey),profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH},
    object:{id:target.id,version:target.version,root:hash(target)},bounds,requested_operation:'INFORM',nodes:[att(leaf),att(target)],transitions:[seal('WHP-TRANSITION-WARRANT-v1',edge,transition.privateKey)]};
  const requirements={scheme:'exact',network:'eip155:8453',amount:'1000000',asset:'0x'+'11'.repeat(20),payTo:'0x'+'22'.repeat(20),maxTimeoutSeconds:300,
    extra:{assetTransferMethod:'eip3009',paymentFlow:'authorization',name:'USDC',version:'2'}};
  return {root,issuer,source,transition,buyer,rootPin,trustBundle,submission,requirements,scope,jurisdiction};
}
