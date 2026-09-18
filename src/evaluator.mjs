import { hash, canonical, demand } from './canonical.mjs';
import { authorize, validateTrust } from './authority.mjs';
import { validateSubmission } from './validation.mjs';
import {attachNamespaceEvidence} from './namespace-authority.mjs';
import { OPERATIONS, profile } from './profile.mjs';

// Pure, bounded evaluator. No network, payments, clock reads, storage, or LLM calls.
export function evaluate(s, trustBundle, rootPin, evaluatedAt, authorityEvidence=[]) {
  validateSubmission(s);
  const trust=attachNamespaceEvidence(validateTrust(trustBundle,rootPin,evaluatedAt),s,authorityEvidence);
  const checks=[], failures=[]; let expiry=Math.min(s.bounds.valid_until,trust.profile.valid_until,evaluatedAt+profile().max_validity_seconds);
  const check=(rule,object,ok,detail)=>{const row={rule,object,passed:!!ok,detail};checks.push(row);if(!ok)failures.push(row);};
  const nodes=new Map(s.nodes.map(e=>[hash(e.payload),e]));
  const incoming=new Map(s.transitions.map(e=>[e.payload.to,e]));
  const root=nodes.get(s.object.root)?.payload;
  check('SOURCE_IDENTITY',s.object.root,root && root.id===s.object.id && root.version===s.object.version,'Root hash, identifier and version must identify the same submitted object.');
  check('ASSESSMENT_TIME',s.object.root,s.bounds.valid_from<=evaluatedAt && evaluatedAt<s.bounds.valid_until,'The assessment must fall within the requested time window.');
  const allOperations=new Set(OPERATIONS);
  const intersect=ops=>{for(const op of [...allOperations])if(!ops.includes(op))allOperations.delete(op);};
  const context={scope:s.bounds.scope,jurisdiction:s.bounds.jurisdiction};
  const within=(x)=>x.scope===context.scope && x.jurisdiction===context.jurisdiction;
  const timeFits=(x)=>x.valid_from<=s.bounds.valid_from && s.bounds.valid_until<=x.valid_until;
  const certificateFits=(c)=>c.valid_from<=s.bounds.valid_from && s.bounds.valid_until<=c.valid_until;
  for(const [h,e] of nodes) {
    const n=e.payload;
    try {const {certificate}=authorize(e,'WHP-SOURCE-ATTESTATION-v1','SOURCE',{...context,operations:n.operations},trust);
      check('SOURCE_AUTHORITY',h,certificateFits(certificate),'An admitted source key must attest within its signed scope, operations and validity.'); expiry=Math.min(expiry,certificate.valid_until);
    } catch(error) { check('SOURCE_AUTHORITY',h,false,'An admitted source key must attest within its signed scope, operations and validity.'); }
    check('SOURCE_ACTIVE',h,n.status==='ACTIVE','Non-active source versions cannot carry operative standing in this profile.');
    check('SOURCE_BOUNDS',h,within(n),'Source jurisdiction and scope must match the requested bounds exactly.');
    check('SOURCE_TIME',h,timeFits(n),'Source validity must contain the requested time window.'); expiry=Math.min(expiry,n.valid_until);
    intersect(n.operations);
    for(const u of n.unknowns)for(const op of u.blocks)allOperations.delete(op);
  }
  const seen=new Set(), visiting=new Set(); let cycle=false,broken=false;
  function visit(h){if(visiting.has(h)){cycle=true;return;}if(seen.has(h))return;if(!nodes.has(h)){broken=true;return;}
    visiting.add(h);const e=incoming.get(h);if(e)for(const p of e.payload.from)visit(p);visiting.delete(h);seen.add(h);}
  visit(s.object.root);
  check('GRAPH_CLOSURE',s.object.root,!cycle&&!broken&&seen.size===nodes.size&&[...incoming.keys()].every(h=>nodes.has(h)),'Every submitted source must be connected to the root; cycles and missing references are forbidden.');
  for(const e of s.transitions) {
    const t=e.payload, h=hash(t), parents=t.from.map(x=>nodes.get(x)?.payload), target=nodes.get(t.to)?.payload;
    try{const {certificate}=authorize(e,'WHP-TRANSITION-WARRANT-v1','TRANSITION',{...context,operations:t.operations},trust);
      check('TRANSITION_AUTHORITY',h,certificateFits(certificate),'A separately admitted transition authority must sign the exact passage.');expiry=Math.min(expiry,certificate.valid_until);
    }catch(error){check('TRANSITION_AUTHORITY',h,false,'A separately admitted transition authority must sign the exact passage.');}
    check('TRANSITION_BOUNDS',h,within(t)&&timeFits(t),'The warrant must contain the requested temporal and jurisdictional bounds.');expiry=Math.min(expiry,t.valid_until);intersect(t.operations);
    check('WARRANT_EVIDENCE',h,t.warrant.evidence_hashes.length>0&&t.warrant.evidence_hashes.every(x=>nodes.has(x)),'The signed warrant must name inspectable evidence in the submitted graph.');
    if(!target||parents.some(x=>!x)){check('TRANSITION_REFERENCES',h,false,'Unknown source or target hash.');continue;}
    let content=false;
    if(t.transform==='COPY')content=parents.length===1&&canonical(target.content)===canonical(parents[0].content)&&target.epistemic_status===parents[0].epistemic_status;
    if(t.transform==='COMPOSE')content=canonical(target.content)===canonical({kind:'COMPOSE',members:[...t.from].sort().map(ph=>({hash:ph,content:nodes.get(ph).payload.content}))})&&target.epistemic_status==='REPORT';
    check('EXACT_TRANSFORMATION',h,content,'COPY preserves content and epistemic status. COMPOSE retains distinct hash-addressed members without fusion.');
    check('QUALIFIERS_PRESERVED',h,parents.every(p=>p.qualifiers.every(q=>target.qualifiers.includes(q))),'All source qualifiers must survive unchanged; this profile permits no waiver.');
    check('UNKNOWNS_PRESERVED',h,parents.every(p=>p.unknowns.every(u=>target.unknowns.some(v=>canonical(u)===canonical(v)))),'Unknowns, their descriptions and blocked operations must survive unchanged.');
    check('NO_FORCE_ESCALATION',h,target.operations.every(op=>t.operations.includes(op)&&parents.every(p=>p.operations.includes(op))),'No target operation may exceed its parents or the exact transition grant.');
  }
  check('REQUESTED_OPERATION',s.object.root,allOperations.has(s.requested_operation),'The requested operation must survive every source, warrant and unresolved blocking unknown.');
  const established=failures.length===0;
  return {
    version:'WHP-STANDING-DECISION-v1.1',evaluated_at:evaluatedAt,submission_hash:hash(s),
    object:s.object,profile:s.profile,bounds:s.bounds,requested_operation:s.requested_operation,
    outcome:established?'ESTABLISHED':'NOT_ESTABLISHED',
    permitted_operations:established?OPERATIONS.filter(op=>allOperations.has(op)):[],
    components:{SOURCE:established?'ESTABLISHED':'NOT_ESTABLISHED',CONTEXT:established?'ESTABLISHED':'NOT_ESTABLISHED',
      RELATION:s.transitions.length?(established?'ESTABLISHED':'NOT_ESTABLISHED'):'NOT_ASSESSED',
      PASSAGE:s.transitions.length?(established?'ESTABLISHED':'NOT_ESTABLISHED'):'NOT_ASSESSED',
      UNKNOWN:established?'ESTABLISHED':'NOT_ESTABLISHED',CONTINUITY:'NOT_ASSESSED',ACTION_BOUNDARY:'NOT_ASSESSED'},
    effective_at:evaluatedAt,expires_at:Math.max(0,expiry),checks,
    unknowns:s.nodes.map(e=>({source_hash:hash(e.payload),unknowns:e.payload.unknowns})),
    assessment_boundary:profile().assessed,not_assessed:profile().not_assessed,
    review_triggers:profile().review_triggers
  };
}
