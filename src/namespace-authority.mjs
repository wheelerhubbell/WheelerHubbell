// Open admission: fixed GitHub HTTPS endpoint, no submitted fetch URL and no signer whitelist.
// The resulting observation is evidence of the assessor's HTTPS check, not a TLS inclusion proof.
import {createHash} from 'node:crypto';
import {canonical,parseStrict,exact,demand,hash,hashBytes,seal,openSeal,keyId,keyObject,timeWindow,array,unique} from './canonical.mjs';

export const NAMESPACE=/^https:\/\/github\.com\/([a-z0-9](?:[a-z0-9-]{0,38}))\/([a-z0-9_][a-z0-9_.-]{0,99})$/;
export const NAMESPACE_SCOPE='github-repository:*';
export const MANIFEST_PATH='.well-known/standing-authority.json';
export function namespaceScope(scope,jurisdiction){return NAMESPACE.test(scope)&&!scope.endsWith('/.')&&!scope.endsWith('/..')&&jurisdiction==='namespace-control';}
export function scoped(c,scope,jurisdiction,role){
  return c.jurisdictions.includes(jurisdiction)&&(c.scopes.includes(scope)||['ISSUER','REGISTRY','DISCOVERY'].includes(role)&&c.scopes.includes(NAMESPACE_SCOPE)&&namespaceScope(scope,jurisdiction));
}
export function validateAuthorityRequests(requests){
  array(requests,8);unique(requests.map(x=>x.namespace));
  for(const x of requests){exact(x,['namespace','manifest_sha256']);demand(namespaceScope(x.namespace,'namespace-control')&&/^[0-9a-f]{64}$/.test(x.manifest_sha256),'NAMESPACE_REQUEST_INVALID');}
}
export function validateManifest(m,namespace){
  exact(m,['version','namespace','valid_from','valid_until','grants']);
  demand(m.version==='WHP-NAMESPACE-GRANTS-v1'&&m.namespace===namespace,'NAMESPACE_MANIFEST_IDENTITY');timeWindow(m);
  array(m.grants,128);demand(m.grants.length>0,'NAMESPACE_GRANTS_REQUIRED');unique(m.grants);
  for(const g of m.grants){
    exact(g,['public_key','role','payload_hashes','scope','jurisdiction','operations','valid_from','valid_until']);keyObject(g.public_key);timeWindow(g);
    demand(['SOURCE','TRANSITION'].includes(g.role)&&g.scope===namespace&&g.jurisdiction==='namespace-control','NAMESPACE_GRANT_SCOPE');
    demand(m.valid_from<=g.valid_from&&g.valid_until<=m.valid_until,'NAMESPACE_GRANT_TIME');
    array(g.payload_hashes,128);unique(g.payload_hashes);demand(g.payload_hashes.length>0&&g.payload_hashes.every(h=>/^[0-9a-f]{64}$/.test(h)),'NAMESPACE_GRANT_HASHES');
    array(g.operations,3);unique(g.operations);demand(g.operations.every(x=>['INFORM','RECOMMEND','EXECUTE'].includes(x)),'NAMESPACE_GRANT_OPERATIONS');
  }
  return m;
}
export function manifestFromObservation(p){
  exact(p,['version','namespace','manifest_raw','manifest_sha256','blob_sha','observed_at']);
  demand(p.version==='WHP-NAMESPACE-OBSERVATION-v1'&&namespaceScope(p.namespace,'namespace-control')&&Number.isSafeInteger(p.observed_at),'NAMESPACE_OBSERVATION_INVALID');
  demand(typeof p.manifest_raw==='string'&&Buffer.byteLength(p.manifest_raw)<=32768,'NAMESPACE_MANIFEST_SIZE');
  const raw=Buffer.from(p.manifest_raw),blob=createHash('sha1').update('blob '+raw.length+'\0').update(raw).digest('hex');
  demand(blob===p.blob_sha,'NAMESPACE_BLOB_MISMATCH');
  const manifest=validateManifest(parseStrict(p.manifest_raw,32768),p.namespace);
  demand(hash(manifest)===p.manifest_sha256,'NAMESPACE_MANIFEST_HASH');return manifest;
}
async function boundedText(response){
  demand(response.ok,'NAMESPACE_UNAVAILABLE',422);
  const reader=response.body.getReader(),parts=[];let size=0;
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();demand(false,'NAMESPACE_RESPONSE_TOO_LARGE',422);}parts.push(Buffer.from(value));}
  return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts));
}
export async function observeNamespaces(service,s){
  validateAuthorityRequests(s.authority);const observations=[];
  for(const requested of s.authority){
    const [,owner,repo]=requested.namespace.match(NAMESPACE);
    const url='https://api.github.com/repos/'+owner+'/'+repo+'/contents/'+MANIFEST_PATH;
    const response=await (service.namespaceFetch??fetch)(url,{headers:{accept:'application/vnd.github+json','user-agent':'WHP-Standing-Namespace-Observer','x-github-api-version':'2022-11-28'},redirect:'error',signal:AbortSignal.timeout(10000)});
    const doc=parseStrict(await boundedText(response),65536);
    demand(doc.type==='file'&&doc.path===MANIFEST_PATH&&doc.encoding==='base64'&&/^[0-9a-f]{40}$/.test(doc.sha),'NAMESPACE_CONTENT_INVALID',422);
    demand(typeof doc.content==='string'&&doc.content.length<=45000,'NAMESPACE_CONTENT_INVALID',422);
    const encoded=doc.content.replace(/\n/g,''),raw=Buffer.from(encoded,'base64');
    demand(raw.toString('base64')===encoded,'NAMESPACE_BASE64_INVALID',422);
    const p={version:'WHP-NAMESPACE-OBSERVATION-v1',namespace:requested.namespace,manifest_raw:new TextDecoder('utf-8',{fatal:true}).decode(raw),manifest_sha256:requested.manifest_sha256,blob_sha:doc.sha,observed_at:service.clock()};
    const m=manifestFromObservation(p);demand(m.valid_from<=p.observed_at&&p.observed_at<m.valid_until,'NAMESPACE_MANIFEST_EXPIRED',422);
    observations.push(seal('WHP-NAMESPACE-OBSERVATION-v1',p,service.privateKey));
  }
  return observations;
}
export function attachNamespaceEvidence(trust,s,evidence){
  array(evidence,8);demand(evidence.length===s.authority.length,'NAMESPACE_EVIDENCE_COUNT');
  const grants=[];
  for(let i=0;i<evidence.length;i++){
    const e=evidence[i],request=s.authority[i],c=trust.keys.get(e.protected.key_id);
    demand(c&&c.roles.includes('ISSUER')&&scoped(c,request.namespace,'namespace-control','ISSUER'),'NAMESPACE_OBSERVER_AUTHORITY');
    const p=openSeal(e,'WHP-NAMESPACE-OBSERVATION-v1',c.public_key),m=manifestFromObservation(p);
    demand(p.namespace===request.namespace&&p.manifest_sha256===request.manifest_sha256,'NAMESPACE_EVIDENCE_BINDING');
    demand(c.valid_from<=p.observed_at&&trust.at<c.valid_until&&!trust.revocations.some(r=>r.key_id===e.protected.key_id&&r.effective_at<=trust.at),'NAMESPACE_OBSERVER_EXPIRED');
    demand(p.observed_at<=trust.at&&trust.at-p.observed_at<=300&&m.valid_from<=trust.at&&trust.at<m.valid_until,'NAMESPACE_EVIDENCE_STALE');
    grants.push(...m.grants);
  }
  return {...trust,namespaceGrants:grants};
}
export function namespaceAuthorize(e,type,role,context,trust){
  const g=trust.namespaceGrants?.find(g=>keyId(g.public_key)===e.protected.key_id&&g.role===role&&g.scope===context.scope&&g.jurisdiction===context.jurisdiction&&g.payload_hashes.includes(hash(e.payload))&&(context.operations??[]).every(o=>g.operations.includes(o))&&g.valid_from<=trust.at&&trust.at<g.valid_until);
  demand(g,'UNKNOWN_AUTHORITY');
  demand(!trust.revocations.some(r=>r.key_id===e.protected.key_id&&r.effective_at<=trust.at),'AUTHORITY_REVOKED');
  const p=openSeal(e,type,g.public_key);
  if(role==='SOURCE'){
    const u=new URL(p.locator),prefix=g.scope+'/';
    demand(!/[\\%]/.test(p.locator)&&u.href===p.locator&&p.locator.startsWith(prefix)&&!u.search&&!u.hash&&!u.username&&!u.password,'NAMESPACE_SOURCE_LOCATOR');
  }
  return {payload:p,certificate:g};
}
