import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {agentCard,a2aRoute,CARRIER_MARK} from '../src/carrier.mjs';
import {hashBytes} from '../src/canonical.mjs';

const origin='https://carrier.invalid';
const exact=await readFile(new URL('../evidence/public-v1/demonstration/TEST-standing-mark.json',import.meta.url),'utf8');
const markFetch=async()=>new Response(exact,{status:200,headers:{'content-type':'application/json'}});

test('A2A Agent Card exposes one transparent transport-only carrier',()=>{
  const card=agentCard(origin);assert.equal(card.supportedInterfaces[0].url,origin+'/a2a');assert.equal(card.supportedInterfaces[0].protocolVersion,'1.0');
  assert.match(card.description,/performs no evaluation/);assert.match(card.skills[0].description,/no evaluation, opinion, relevance determination/);
});

test('carrier returns the exact existing Mark bytes without adding authority',async()=>{
  assert.equal(hashBytes(exact),CARRIER_MARK.sha256);
  const request=new Request(origin+'/a2a',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:'one',method:'SendMessage',params:{message:{messageId:'incoming',role:'ROLE_USER',parts:[{text:'Show the Mark.'}]}}})});
  const response=await a2aRoute(origin,request,{markFetch});assert.equal(response.status,200);const body=await response.json();
  assert.equal(body.result.message.role,'ROLE_AGENT');const artifact=body.result.message.parts[1].data;assert.equal(artifact.role,'TRANSPORT_ONLY');assert.equal(artifact.mark.exact_utf8,exact);assert.equal(hashBytes(artifact.mark.exact_utf8),CARRIER_MARK.sha256);assert.match(artifact.boundaries.join(' '),/states no opinion/);
});

test('carrier fails closed when immutable Mark bytes do not match',async()=>{
  const request=new Request(origin+'/a2a',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:2,method:'SendMessage',params:{message:{messageId:'incoming',role:'ROLE_USER',parts:[{text:'Show the Mark.'}]}}})});
  const response=await a2aRoute(origin,request,{markFetch:async()=>new Response('{}',{status:200})});const body=await response.json();assert.equal(response.status,503);assert.equal(body.error.code,-32603);
});
