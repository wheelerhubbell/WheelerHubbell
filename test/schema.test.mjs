import test from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {setup,resignTarget} from './fixtures.mjs';import {canonical} from '../src/canonical.mjs';

test('published JSON Schemas validate submission, authority, requirements, positive Mark and negative assessment',async()=>{const x=await setup(),dir=mkdtempSync(join(tmpdir(),'whp-schemas-'));try{
  const positive=await x.purchase();const negative=resignTarget(x.f,n=>{n.qualifiers=[];});negative.client_reference+='negative';const denied=await x.purchase(negative);assert.equal(denied.response.status,200);
  const files={'submission.json':canonical(x.f.submission),'trust.json':canonical(x.f.trustBundle),'requirements.json':canonical(x.f.requirements),'mark.json':positive.bytes,'negative.json':denied.bytes};for(const [name,bytes] of Object.entries(files))writeFileSync(join(dir,name),bytes);
  const args=[new URL('../scripts/check-schemas.py',import.meta.url).pathname];for(const [schema,file] of [['submission','submission.json'],['trust-bundle','trust.json'],['payment-requirements','requirements.json'],['result','mark.json'],['result','negative.json']])args.push(new URL('../schemas/'+schema+'.schema.json',import.meta.url).pathname,join(dir,file));
  const output=execFileSync('python3',args,{encoding:'utf8'});assert.equal((output.match(/INSTANCE_VALID/g)??[]).length,5);
}finally{await x.store.close();rmSync(dir,{recursive:true,force:true});}});
test('discovery schema links resolve on the actual service and identify the correct wire contract',async()=>{const x=await setup();try{const r=await x.request('GET','/.well-known/whp-standing.json'),d=await r.json();for(const link of [d.input_schema,d.result_schema]){const res=await x.request('GET',link);assert.equal(res.status,200);assert.match((await res.json()).$id,/urn:whp:standing:v1:/);}}finally{await x.store.close();}});
