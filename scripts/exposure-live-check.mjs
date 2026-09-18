// Controlled public-only traversal. No producer imports, wallet, keys or DB credentials.
import {createHash,createPublicKey,generateKeyPairSync,sign,verify,randomBytes} from 'node:crypto';
import {mkdir,writeFile} from 'node:fs/promises';
const origin=process.argv[2],out=process.argv[3];
if(!origin?.startsWith('https://')||!out)throw Error('Usage: node exposure-live-check.mjs HTTPS_ORIGIN OUTPUT.json');
const canonical=x=>x===null||typeof x!=='object'?JSON.stringify(x):Array.isArray(x)?'['+x.map(canonical).join(',')+']':'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
const sha=x=>createHash('sha256').update(x).digest('hex');
const trace=[],report={checked_at:new Date().toISOString(),origin,kind:'CONTROLLED_PUBLIC_ONLY_TRAVERSAL',producer_imports:false,wallet_authorizations:0,settlements:0,independent_external_encounter:false,institutional_root_admission:false};
async function request(url,options={}){const r=await fetch(url,{...options,headers:{'user-agent':'WHP-controlled-exposure-probe/1',...options.headers},redirect:'error',signal:AbortSignal.timeout(30000)});const raw=await r.text();trace.push({url,method:options.method??'GET',status:r.status,sha256:sha(raw),request_id:r.headers.get('x-nf-request-id'),link:r.headers.get('link'),date:r.headers.get('date')});return {r,raw,json:()=>JSON.parse(raw)};}
const require=(condition,name)=>{if(!condition)throw Error(name);};
const open=(e,type,key)=>{require(e.protected.type===type,'wrong signed type');require(e.protected.key_id===sha(Buffer.from(key,'base64')),'signer key id');require(verify(null,Buffer.from(canonical({protected:e.protected,payload:e.payload})),createPublicKey({key:Buffer.from(key,'base64'),format:'der',type:'spki'}),Buffer.from(e.signature,'base64')),'signature');return e.payload;};
try{
 const catalog=await request(origin+'/.well-known/api-catalog');require(catalog.r.status===200,'catalog unavailable');
 const metadata=catalog.json().linkset.find(x=>x['service-meta']);require(metadata,'missing service metadata');
 const contractResponse=await request(metadata['service-meta'][0].href);const c=contractResponse.json();require(contractResponse.r.status===200,'contract unavailable');
 const paths=['/llms.txt','/sitemap.xml','/robots.txt','/server.json','/discovery/applicability.json','/discovery/recursive-use.json','/discovery/capability.json','/discovery/provider-index.json','/.well-known/x402','/openapi.json'];
 const surfaces=await Promise.all(paths.map(async p=>{const v=await request(origin+p);require(v.r.status===200,'surface unavailable '+p);return [p,v];}));
 const map=new Map(surfaces);require(map.get('/discovery/applicability.json').json().contexts.length===13,'context count');
 require(map.get('/llms.txt').raw.includes('/discovery/recursive-use.json'),'llms handoff join');
 const provider=map.get('/discovery/provider-index.json').json().providers.find(x=>x.capability_class===c.capability_class);require(provider,'provider class mismatch');
 const resolved=await request(provider.resolution_url),envelope=resolved.json(),p=envelope.payload,t=p.trust_bundle,now=Math.floor(Date.now()/1000);
 require(sha(Buffer.from(t.root_public_key,'base64'))===c.root_pin,'root commitment mismatch');
 const cert=t.certificates.find(x=>sha(Buffer.from(x.payload.public_key,'base64'))===envelope.protected.key_id);require(cert,'discovery signer absent');
 open(cert,'WHP-AUTHORITY-CERTIFICATE-v1',t.root_public_key);require(cert.payload.roles.includes('DISCOVERY'),'discovery role absent');
 const status=open(t.status_snapshot,'WHP-TRUST-STATUS-v1',t.root_public_key);require(status.valid_from<=now&&now<status.valid_until,'trust expired');
 open(envelope,'WHP-CAPABILITY-RESOLUTION-v1',cert.payload.public_key);require(p.observed_at<=now&&now<p.valid_until,'resolution expired');require(p.service_contract.sha256===sha(canonical(c)),'contract commitment');
 report.resolution_signature_and_contract_commitment_verified=true;
 const verification=(await request(c.verification_url)).json();const verifier=await request(verification.source.url);require(sha(verifier.raw)===verification.source.sha256&&sha(verifier.raw)===c.public_contract.verifier_sha256,'verifier bytes mismatch');
 report.verifier_bytes_verified=true;report.verifier_execution=false;report.mark_verification='NOT_EXECUTED_NO_PAID_MARK_SUPPLIED';
 const rpc=async(method,params)=>{const x=await request(c.mcp_url,{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});require(x.r.status===200,'MCP unavailable');const data=x.json();require(!data.error,'MCP error');return data.result;};
 await rpc('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'WHP-controlled-exposure-probe',version:'1'}});
 const resources=await rpc('resources/list',{});require(resources.resources.some(x=>x.uri===origin+'/discovery/recursive-use.json'),'MCP handoff missing');
 await rpc('resources/read',{uri:origin+'/discovery/applicability.json'});report.mcp_resources_verified=resources.resources.length;
 const pair=generateKeyPairSync('ed25519'),pub=pair.publicKey.export({format:'der',type:'spki'}).toString('base64');
 const values={scope:c.supported_scopes[0],jurisdiction:c.supported_jurisdictions[0],now_minus_1:now-1,now_plus_60:now+60,object_id:'controlled-exposure-probe',object_version:'1',object_content:{statement:'Unadmitted public boundary probe. No sale or positive standing.'},operation:'INFORM',client_reference:'exposure_'+randomBytes(12).toString('hex'),public_key:pub};
 const fill=x=>x&&typeof x==='object'?(Object.keys(x).length===1&&x.$input?values[x.$input]:Array.isArray(x)?x.map(fill):Object.fromEntries(Object.entries(x).map(([k,v])=>[k,fill(v)]))):x;
 const seal=(type,payload)=>{const protectedHeader={type,algorithm:'Ed25519',canonicalization:'WHP-JCS-I1',key_id:sha(Buffer.from(pub,'base64'))};return {protected:protectedHeader,payload,signature:sign(null,Buffer.from(canonical({protected:protectedHeader,payload})),pair.privateKey).toString('base64')};};
 const node=fill(c.cold_probe.source_payload);values.node_hash=sha(canonical(node));values.signed_node=seal(c.cold_probe.source_protected.type,node);const submission=fill(c.cold_probe.submission_template),raw=canonical(submission),path=new URL(c.purchase.url).pathname;
 const proof=seal('WHP-CLIENT-PROOF-v1',{method:'POST',path,body_hash:sha(raw),issued_at:now,expires_at:now+120,nonce:randomBytes(16).toString('hex')});
 const q=await request(c.purchase.url,{method:'POST',headers:{'content-type':'application/json','whp-client-proof':Buffer.from(canonical(proof)).toString('base64')},body:raw});
 require(q.r.status===402,'unpaid boundary not reached: '+q.r.status);const terms=q.json();require(canonical(terms.accepts[0])===canonical(c.purchase.requirements),'payment terms mismatch');
 require(canonical(JSON.parse(Buffer.from(q.r.headers.get('payment-required'),'base64').toString()))===canonical(terms),'payment header/body mismatch');
 const quote=terms.extensions['whp-standing'].info.quote;const issuer=t.certificates.find(x=>sha(Buffer.from(x.payload.public_key,'base64'))===quote.protected.key_id);require(issuer?.payload.roles.includes('ISSUER'),'quote issuer absent');open(quote,'WHP-STANDING-QUOTE-v1',issuer.payload.public_key);
 report.unpaid_acquisition_entry_verified=true;report.bazaar_extension_present=Boolean(terms.extensions.bazaar);report.publication=true;report.external_reachability=true;report.controlled_machine_interpretation=true;report.actual_buyer_relevance='UNKNOWN';report.completed_acquisition='NOT_OBSERVED';report.subsequent_mark_encounter='NOT_OBSERVED';report.recursive_acquisition='NOT_OBSERVED';report.state='PASS';
}catch(e){report.state='FAIL';report.error=e.message;process.exitCode=1;}
report.trace=trace;
await mkdir(new URL('.',new URL('file://'+out)).pathname,{recursive:true});await writeFile(out,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
