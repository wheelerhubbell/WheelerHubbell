import test from 'node:test';import assert from 'node:assert/strict';
import {setup,fixture,NOW,refreshTrustStatus} from './fixtures.mjs';
import {clone,hash,seal,keyId,publicDer,canonical} from '../src/canonical.mjs';
import {evaluate} from '../src/evaluator.mjs';import {validateTrust} from '../src/authority.mjs';
import {validateSubmission} from '../src/validation.mjs';
import {pythonVerifier} from '../verify/python-verifier.mjs';

test('removing a signed revocation cannot silently change the admitted root status',()=>{const f=fixture();f.trustBundle.revocations.push(seal('WHP-KEY-REVOCATION-v1',{key_id:keyId(publicDer(f.source.privateKey)),effective_at:NOW-1,reason:'Test removal'},f.root.privateKey));refreshTrustStatus(f);f.trustBundle.revocations=[];assert.throws(()=>validateTrust(f.trustBundle,f.rootPin,NOW),/TRUST_STATUS_MANIFEST_MISMATCH/);});
test('removing an authority certificate cannot evade the signed status manifest',()=>{const f=fixture();f.trustBundle.certificates.pop();assert.throws(()=>validateTrust(f.trustBundle,f.rootPin,NOW),/TRUST_STATUS_MANIFEST_MISMATCH/);});
test('expired root status does not remain fresh because its signature is valid',()=>{const f=fixture();assert.throws(()=>validateTrust(f.trustBundle,f.rootPin,NOW+604801),/PROFILE_NOT_AUTHORIZED|TRUST_STATUS_EXPIRED/);});
test('ambiguous duplicated unknown IDs are rejected before evaluation/payment',()=>{const f=fixture(),u=clone(f.submission.nodes[0].payload.unknowns[0]);u.description='Another description under the same ID';f.submission.nodes[0].payload.unknowns.push(u);assert.throws(()=>validateSubmission(f.submission),/DUPLICATE_ITEM/);});
test('COMPOSE preserves separate exact member identities, qualifiers and unknowns',()=>{
  const f=fixture(),s=clone(f.submission),a=clone(s.nodes[0].payload),b=clone(a);b.id='other-observation';b.content={statement:'A distinct assertion, not a blended assertion.',color:'blue'};b.locator='urn:whp:test:source-2';
  const from=[hash(a),hash(b)].sort(),map=new Map([[hash(a),a],[hash(b),b]]),target=clone(s.nodes[1].payload);target.content={kind:'COMPOSE',members:from.map(h=>({hash:h,content:map.get(h).content}))};
  s.nodes=[a,b,target].map(n=>seal('WHP-SOURCE-ATTESTATION-v1',n,f.source.privateKey));s.object.root=hash(target);
  const edge={...s.transitions[0].payload,from,to:hash(target),transform:'COMPOSE',warrant:{statement:'Compose distinct exact members without blending their content.',evidence_hashes:from}};
  s.transitions=[seal('WHP-TRANSITION-WARRANT-v1',edge,f.transition.privateKey)];assert.equal(evaluate(s,f.trustBundle,f.rootPin,NOW).outcome,'ESTABLISHED');
});
test('graph cycle is denied rather than treated as self-grounding provenance',()=>{const f=fixture(),s=clone(f.submission),leaf=hash(s.nodes[0].payload),target=s.object.root;const reverse={...s.transitions[0].payload,from:[target],to:leaf};s.transitions.push(seal('WHP-TRANSITION-WARRANT-v1',reverse,f.transition.privateKey));const r=evaluate(s,f.trustBundle,f.rootPin,NOW);assert.equal(r.outcome,'NOT_ESTABLISHED');assert.equal(r.checks.find(c=>c.rule==='GRAPH_CLOSURE').passed,false);});
test('authority revoked after issuance limits current standing without rewriting historical Mark',async()=>{
  let now=NOW;const x=await setup({clock:()=>now});try{const issued=await x.purchase();now=NOW+10;x.f.trustBundle.revocations.push(seal('WHP-KEY-REVOCATION-v1',{key_id:keyId(publicDer(x.f.source.privateKey)),effective_at:NOW+5,reason:'Test post-issuance revocation'},x.f.root.privateKey));refreshTrustStatus(x.f);
    const status=await x.request('GET','/v1/registry/'+JSON.parse(issued.bytes).payload.purchase_id);const registry=await status.text();assert.equal(JSON.parse(registry).payload.status,'LIMITED');
    const report=await pythonVerifier({rootPin:x.f.rootPin,allowTest:true})(issued.bytes,registry,now);assert.equal(report.current_standing,'LIMITED');
    const stored=await x.request('GET','/v1/purchases/'+JSON.parse(issued.bytes).payload.purchase_id+'/result');assert.equal(await stored.text(),issued.bytes);
  }finally{await x.store.close();}
});
test('appeal receipt is durable/idempotent and does not confer standing',async()=>{const x=await setup();try{const r=await x.purchase(),id=JSON.parse(r.bytes).payload.purchase_id;const review={client_reference:'review-idempotency-test-0001',reviewer_key:x.f.submission.buyer_key,purchase_id:id,reason:'Challenge the source attribution in this fixture.',evidence_hashes:[x.f.submission.object.root]};
  const a=await x.request('POST','/v1/reviews',canonical(review)),b=await x.request('POST','/v1/reviews',canonical(review));assert.equal(a.status,201);assert.equal(await a.text(),await b.text());review.reason='Different challenge';const conflict=await x.request('POST','/v1/reviews',canonical(review));assert.equal(conflict.status,409);assert.equal((await x.store.events(id)).length,1);
}finally{await x.store.close();}});
test('input depth reserves envelope capacity before any payment processing',()=>{const f=fixture();let deep={};for(let i=0;i<55;i++)deep={nested:deep};f.submission.nodes[0].payload.content=deep;assert.throws(()=>validateSubmission(f.submission),/JSON_DEPTH/);});
