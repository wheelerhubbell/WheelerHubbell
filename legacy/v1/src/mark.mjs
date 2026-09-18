import { seal, hash, canonical, keyId, publicDer, demand } from './canonical.mjs';
import { validateTrust, issuerAuthority } from './authority.mjs';
import { evaluate } from './evaluator.mjs';
import { profile } from './profile.mjs';
import {protocol,identity} from './protocol.mjs';
import {validateWire} from './wire-schema.mjs';
import resultSchema from '../schemas/result.schema.json' with {type:'json'};

export function assembleResult(row,privateKey,rootPin) {
  demand(row.state==='SETTLED' && row.settlement && row.decision,'RESULT_NOT_READY',503);
  const trust=validateTrust(row.trust_bundle,rootPin,row.issued_at);
  const cert=issuerAuthority(keyId(publicDer(privateKey)),row.submission.bounds.scope,row.submission.bounds.jurisdiction,trust);
  demand(row.request_hash===hash(row.submission),'RESULT_SUBMISSION_COMMITMENT',503);
  demand(hash(evaluate(row.submission,row.trust_bundle,rootPin,row.decision.evaluated_at))===hash(row.decision),'RESULT_DECISION_REPLAY',503);
  const isMark=row.decision.outcome==='ESTABLISHED';
  const p={
    version:'WHP-STANDING-RESULT-v1',environment:trust.profile.environment,
    issuer:trust.profile.issuer,issuer_key_id:keyId(publicDer(privateKey)),
    purchase_id:row.id,mark_id:isMark?'WHP-SM-'+row.id:null,
    issued_at:row.issued_at,effective_at:row.decision.effective_at,
    expires_at:Math.min(row.decision.expires_at,cert.valid_until),
    object:row.submission.object,profile:profile(),profile_authorization:row.trust_bundle.profile_authorization,
    authority:row.trust_bundle,
    submission:row.submission,submission_hash:row.request_hash,
    decision_record:row.decision,decision_record_ref:'urn:sha256:'+hash(row.decision),
    standing:isMark?{operation:row.submission.requested_operation,components:row.decision.components,bounds:row.submission.bounds}:null,
    commerce:{quote:row.quote,payment_identity:row.payment_key,payment_payload:row.payment_payload,
      settlement:row.settlement,assessment_paid_by:row.payment_payload.payload.authorization.from,
      relationship:trust.profile.environment==='TEST'?'Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.':'The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.',
      assessor:'WHP Standing deterministic Structured Passage evaluator 1.0.0'},
    retrieval:{purchase_path:'/v1/purchases/'+row.id,result_path:'/v1/purchases/'+row.id+'/result',
      registry_path:'/v1/registry/'+row.id,authentication:'Buyer Ed25519 proof bound to HTTP method, path and body',additional_charge:false},
    limitations:profile().not_assessed,
    protocol:protocol(),
    discovery:identity(row.discovery_identity.resolution_url,row.id,rootPin,trust.profile.environment),
    current_status_rule:'This immutable record proves issuance-time assessment. Current standing requires a fresh signed registry response and current trust/revocation information.'
  };
  const type=isMark?'WHP-STANDING-MARK-v1':'WHP-STANDING-ASSESSMENT-v1';
  const envelope=seal(type,p,privateKey);validateWire(envelope,resultSchema);return canonical(envelope)+'\n';
}
