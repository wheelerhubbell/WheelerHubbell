import { demand, exact, text, array, unique, timeWindow, canonical, hash, keyObject } from './canonical.mjs';
import { PROFILE_ID, PROFILE_VERSION, PROFILE_HASH, OPERATIONS } from './profile.mjs';
export const HASH_RE = /^[0-9a-f]{64}$/;
const digest = (s,p='$') => demand(typeof s==='string' && HASH_RE.test(s),'HASH_INVALID',400,p);
const strings = (a,p,max=128) => { array(a,max,p); a.forEach((s,i)=>text(s,`${p}[${i}]`)); unique(a,p); };
function ops(a,p) { strings(a,p,3); demand(a.every(x=>OPERATIONS.includes(x)), 'OPERATION_INVALID',400,p); }
export function envelopeShape(e,p,type) {
  exact(e,['protected','payload','signature'],p); exact(e.protected,['type','algorithm','canonicalization','key_id'],p+'.protected');
  digest(e.protected.key_id,p+'.protected.key_id'); text(e.signature,p+'.signature',128);
  demand(e.protected.type===type&&e.protected.algorithm==='Ed25519'&&e.protected.canonicalization==='WHP-JCS-I1','ENVELOPE_TYPE_INVALID',400,p+'.protected');
  demand(/^[A-Za-z0-9+/]{86}==$/.test(e.signature)&&Buffer.from(e.signature,'base64').toString('base64')===e.signature,'SIGNATURE_FORMAT_INVALID',400,p+'.signature');
}
export function validateSubmission(s) {
  canonical(s,16); exact(s,['version','client_reference','buyer_key','profile','object','bounds','requested_operation','nodes','transitions']);
  demand(s.version==='WHP-STANDING-SUBMISSION-v1','VERSION_UNSUPPORTED');
  demand(typeof s.client_reference==='string' && /^[A-Za-z0-9_-]{16,96}$/.test(s.client_reference),'CLIENT_REFERENCE_INVALID');
  keyObject(s.buyer_key);
  exact(s.profile,['id','version','sha256']);
  demand(s.profile.id===PROFILE_ID && s.profile.version===PROFILE_VERSION && s.profile.sha256===PROFILE_HASH,'PROFILE_UNSUPPORTED');
  exact(s.object,['id','version','root']); text(s.object.id); text(s.object.version); digest(s.object.root);
  exact(s.bounds,['scope','jurisdiction','valid_from','valid_until']); text(s.bounds.scope);text(s.bounds.jurisdiction);timeWindow(s.bounds);
  demand(OPERATIONS.includes(s.requested_operation),'OPERATION_INVALID');
  array(s.nodes,64,'$.nodes'); demand(s.nodes.length>0,'NODES_REQUIRED'); array(s.transitions,64,'$.transitions');
  for(const [i,e] of s.nodes.entries()) {
    const p=`$.nodes[${i}]`; envelopeShape(e,p,'WHP-SOURCE-ATTESTATION-v1'); const n=e.payload;
    exact(n,['id','version','content','locator','epistemic_status','qualifiers','unknowns','operations','scope','jurisdiction','valid_from','valid_until','status','prior_hash'],p+'.payload');
    for(const k of ['id','version','locator','scope','jurisdiction']) text(n[k],p+'.'+k);
    demand(['OBSERVATION','REPORT','FINDING','INFERENCE','HYPOTHESIS','UNKNOWN'].includes(n.epistemic_status),'EPISTEMIC_STATUS_INVALID',400,p);
    demand(['ACTIVE','CORRECTED','SUPERSEDED','DISPUTED','WITHDRAWN'].includes(n.status),'LINEAGE_STATUS_INVALID',400,p);
    demand(n.prior_hash===null || HASH_RE.test(n.prior_hash),'PRIOR_HASH_INVALID',400,p); timeWindow(n,p); ops(n.operations,p+'.operations'); strings(n.qualifiers,p+'.qualifiers');
    array(n.unknowns,64,p+'.unknowns'); unique(n.unknowns,p+'.unknowns');
    unique(n.unknowns.map(u=>u.id),p+'.unknowns.id');
    for(const u of n.unknowns) {exact(u,['id','description','blocks']);text(u.id);text(u.description);ops(u.blocks,p+'.unknowns.blocks');}
  }
  unique(s.nodes.map(e=>hash(e.payload))); unique(s.nodes.map(e=>[e.payload.id,e.payload.version]));
  for(const [i,e] of s.transitions.entries()) {
    const p=`$.transitions[${i}]`;envelopeShape(e,p,'WHP-TRANSITION-WARRANT-v1');const t=e.payload;
    exact(t,['from','to','transform','operations','scope','jurisdiction','valid_from','valid_until','warrant'],p+'.payload');
    array(t.from,64,p+'.from');demand(t.from.length>0,'TRANSITION_SOURCE_REQUIRED',400,p);t.from.forEach(x=>digest(x,p));unique(t.from);digest(t.to,p);
    demand(['COPY','COMPOSE'].includes(t.transform),'TRANSFORM_UNSUPPORTED',400,p);
    ops(t.operations,p+'.operations');text(t.scope);text(t.jurisdiction);timeWindow(t,p);
    exact(t.warrant,['statement','evidence_hashes']);text(t.warrant.statement);array(t.warrant.evidence_hashes,64);t.warrant.evidence_hashes.forEach(x=>digest(x,p));unique(t.warrant.evidence_hashes);
  }
  unique(s.transitions.map(e=>e.payload.to));
  return s;
}
