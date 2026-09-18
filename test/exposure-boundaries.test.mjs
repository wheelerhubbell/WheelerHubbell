import test from 'node:test';
import assert from 'node:assert/strict';
import {applicability,recursiveUse,exposurePaths,exposureLinks} from '../src/exposure.mjs';
import {discoveryRoute} from '../src/discovery.mjs';
import {mcpRoute} from '../src/mcp.mjs';
import {verifySourceCommitments} from '../scripts/netlify-production-target.mjs';
const origin='https://discovery-check.invalid',service={origin};
test('recovered contexts retain provenance and narrower current semantics',()=>{
 const a=applicability(origin);assert.equal(a.contexts.length,13);assert.equal(new Set(a.contexts.map(x=>x.id)).size,13);
 for(const x of a.contexts){assert.match(x.source,/45365dab000277460d741c8dd536781536f6f22d/);assert.match(x.adaptation,/not the prior DIP/);}
 assert.equal(a.taxonomy_recovery.observed_ingested_count,1012);assert.equal(a.taxonomy_recovery.occupation_mapping_recovered,false);
 assert.equal(a.kind,'DISCOVERY_CONTEXTS_NOT_AUTHORITY_PROFILES');
});
test('handoff does not authorize disclosure, automatic spending or forced WHP use',()=>{
 const r=recursiveUse(origin);assert.match(r.handoff.payload,/Exact original Mark bytes/);assert.match(r.handoff.permission,/authorized to disclose/);
 assert.match(r.encounter.negative_rule,/Absence of a Mark never implies a duty/);assert.equal(r.observed_recursive_acquisition,false);
});
test('new discovery GET and HEAD routes share generated content',async()=>{
 for(const path of exposurePaths.slice(0,2)){
  const r=await discoveryRoute(service,new Request(origin+path));assert.equal(r.status,200);assert.equal((await r.json()).contract_url,origin+'/v1/contract');
  const h=await discoveryRoute(service,new Request(origin+path,{method:'HEAD'}));assert.equal(h.status,200);assert.equal(await h.text(),'');
  assert.equal(await discoveryRoute(service,new Request(origin+path,{method:'POST'})),null);
 }
});
test('MCP exposes and reads bounded resources through the same canonical routes',async()=>{
 service.handle=req=>discoveryRoute(service,req);
 const call=(method,params)=>mcpRoute(service,new Request(origin+'/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})}));
 const list=await (await call('resources/list',{})).json();assert.equal(list.result.resources.length,6);
 const uri=origin+'/discovery/applicability.json';const result=await (await call('resources/read',{uri})).json();assert.equal(JSON.parse(result.result.contents[0].text).contexts.length,13);
});
test('discovery entrypoints link to the new surfaces without exposing private results',async()=>{
 for(const path of ['/llms.txt','/sitemap.xml']){const body=await (await discoveryRoute(service,new Request(origin+path))).text();for(const target of exposurePaths.slice(0,2))assert.ok(body.includes(origin+target));assert.ok(!body.includes('/v1/purchases/'));}
 const metadata=await (await discoveryRoute(service,new Request(origin+'/server.json'))).json();assert.match(metadata.repository.url,/WheelerHubbellPublishingStandingMark$/);assert.ok(metadata.description.length<=100);
 assert.match(exposureLinks(origin),/rel="api-catalog"/);assert.match(exposureLinks(origin),/recursive-use/);
});
test('frozen profile, Mark contract and verifier bytes remain unchanged',async()=>{assert.equal((await verifySourceCommitments()).contract_regenerated,false);});
test('x402 discovery advertises the actual gated resource, not generic buyer compatibility',async()=>{
 const s={origin,requirements:{scheme:'exact',amount:'1000000'}};
 const a=await (await discoveryRoute(s,new Request(origin+'/.well-known/x402'))).json();
 assert.deepEqual(a.resources,[origin+'/v1/evaluations']);assert.equal(a.payment.generic_random_nonce_client_compatible,false);assert.deepEqual(a.payment.requirements,s.requirements);
 const b=await (await discoveryRoute(s,new Request(origin+'/openapi.json'))).json();assert.equal(b.servers[0].url,origin);
});
