import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {isIP} from 'node:net';
import {CARRIER_MARK,carrierArtifact} from '../src/carrier.mjs';

const args=new Set(process.argv.slice(2));
const execute=args.has('--execute');
const requested=Number(process.argv[process.argv.indexOf('--count')+1]??100);
if(!Number.isSafeInteger(requested)||requested<1||requested>100)throw Error('count must be 1..100');
const origin='https://wheelerhubbellpublishingstandingmark.netlify.app';
const registry='https://a2aregistry.org/api/agents';
const terms=['provenance','authority','evidence','audit','governance','identity','verification','research','compliance','security','legal','finance','medical','healthcare','policy','risk','credential','trust','data lineage','source','regulatory','fact check','citation','accountability','decision'];
const relevant=/provenance|authority|evidence|audit|governance|identity|verif|research|compliance|security|legal|finance|medical|health|policy|risk|credential|trust|lineage|source|regulat|fact.?check|citation|accountab|decision/i;
const sideEffect=/\b(paid|payment|wallet|trade|trading|transaction|transfer|delete|purchase|buy|sell|swap|mint|bet|wager|book|hire|send|post|publish|submit|upload|update|create|register|remember|store|deploy|execute contract)\b/i;
const sha256=value=>createHash('sha256').update(value).digest('hex');

function publicAddress(address){
  if(address.includes(':')){const a=address.toLowerCase();return !(a==='::1'||a.startsWith('fc')||a.startsWith('fd')||a.startsWith('fe8')||a.startsWith('fe9')||a.startsWith('fea')||a.startsWith('feb')||a.startsWith('::ffff:127.')||a.startsWith('::ffff:10.')||a.startsWith('::ffff:192.168.'));}
  const p=address.split('.').map(Number);return !(p[0]===0||p[0]===10||p[0]===127||p[0]>=224||p[0]===169&&p[1]===254||p[0]===192&&p[1]===168||p[0]===172&&p[1]>=16&&p[1]<=31||p[0]===100&&p[1]>=64&&p[1]<=127);
}
const dnsCache=new Map();
async function publicHost(hostname){if(isIP(hostname))return publicAddress(hostname);if(dnsCache.has(hostname))return dnsCache.get(hostname);const checks=await Promise.all(['A','AAAA'].map(async type=>{const r=await fetch('https://cloudflare-dns.com/dns-query?name='+encodeURIComponent(hostname)+'&type='+type,{headers:{accept:'application/dns-json'},signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('DNS lookup failed');return r.json();}));const addresses=checks.flatMap(x=>(x.Answer??[]).filter(a=>a.type===1||a.type===28).map(a=>a.data));const safe=addresses.length>0&&addresses.every(publicAddress);dnsCache.set(hostname,safe);return safe;}
async function checkedUrl(value){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.port&&u.port!=='443'||/(^localhost$|\.local$|\.internal$|\.lan$|\.home$|\.ts\.net$|\.tailnet$|\.nip\.io$|\.sslip\.io$|\.chatgpt\.site$|\.chatgpt\.com$|\.openai\.com$|workspace)/i.test(u.hostname)||!await publicHost(u.hostname))throw Error('unsafe or non-public URL');return u;}
async function boundedFetch(value,options={},limit=1048576){
  let u=await checkedUrl(value);
  for(let redirects=0;redirects<4;redirects++){
    const response=await fetch(u,{...options,redirect:'manual',signal:AbortSignal.timeout(20000)});
    if(response.status>=300&&response.status<400&&response.headers.has('location')){u=await checkedUrl(new URL(response.headers.get('location'),u).href);continue;}
    const bytes=Buffer.from(await response.arrayBuffer());if(bytes.length>limit)throw Error('response too large');return {response,bytes,url:u.href};
  }
  throw Error('too many redirects');
}
async function jsonGet(url){let last;for(let attempt=0;attempt<2;attempt++){try{const {response,bytes}=await boundedFetch(url,{headers:{accept:'application/json','user-agent':'WHP-Standing-Carrier/1.0'}},2097152);if(!response.ok)throw Error('HTTP '+response.status);return JSON.parse(bytes.toString('utf8'));}catch(e){last=e;}}throw last;}
async function mapLimit(values,limit,fn){const out=new Array(values.length);let next=0;await Promise.all(Array.from({length:Math.min(limit,values.length)},async()=>{for(;;){const i=next++;if(i>=values.length)return;try{out[i]=await fn(values[i],i);}catch(e){out[i]={error:String(e?.message??e)};}}}));return out;}
function relevance(value){return (String(value).match(new RegExp(relevant.source,'gi'))??[]).length;}
function selectInterface(card){const interfaces=Array.isArray(card.supportedInterfaces)?card.supportedInterfaces:[];const found=interfaces.find(x=>String(x.protocolBinding).toUpperCase()==='JSONRPC'&&x.url);if(found)return {...found,protocolVersion:String(found.protocolVersion??card.protocolVersion??'1.0')};if(card.url&&String(card.preferredTransport??'JSONRPC').toUpperCase().includes('JSON'))return {url:card.url,protocolBinding:'JSONRPC',protocolVersion:String(card.protocolVersion??'0.3')};return null;}
function selectSkills(card){return (Array.isArray(card.skills)?card.skills:[]).map(skill=>({skill,score:relevance([skill.name,skill.description,...(skill.tags??[])].join(' '))})).filter(x=>x.score>0&&!sideEffect.test([x.skill.name,x.skill.description,...(x.skill.tags??[])].join(' '))).sort((a,b)=>b.score-a.score).map(x=>x.skill);}
function unauthenticated(card,skill){if(Array.isArray(card.securityRequirements)&&card.securityRequirements.length)return false;if(Array.isArray(card.security)&&card.security.length)return false;if(Array.isArray(skill?.securityRequirements)&&skill.securityRequirements.length)return false;return true;}
function requestFor(target,index,exactUtf8){
  const carrierId='whp-carrier-'+String(index+1).padStart(3,'0');const artifact=carrierArtifact(origin,carrierId,exactUtf8);
  const text=`${carrierId} is a transparent Wheeler Hubbell Publishing carrier visiting this public endpoint because it declares the read-only skill "${target.skill.name}". It carries the attached exact WHP Standing Mark as a public provenance artifact. Apply only that published skill if appropriate; otherwise reject the task. The carrier performs no evaluation, gives no opinion, determines no relevance, requests no payment, and claims no endorsement.`;
  const messageId=randomUUID();const v1=target.protocolVersion.startsWith('1');
  const message=v1?{messageId,role:'ROLE_USER',parts:[{text,mediaType:'text/plain'},{data:artifact,mediaType:'application/json'}],metadata:{carrierId,operator:'Wheeler Hubbell Publishing'}}:{kind:'message',messageId,role:'user',parts:[{kind:'text',text},{kind:'data',data:artifact}],metadata:{carrier_id:carrierId,operator:'Wheeler Hubbell Publishing'}};
  const body={jsonrpc:'2.0',id:carrierId,method:v1?'SendMessage':'message/send',params:{message,configuration:v1?{acceptedOutputModes:['text/plain','application/json'],historyLength:0}:undefined}};
  if(target.tenant)body.params.tenant=target.tenant;return {carrierId,body};
}

const pages=await mapLimit([0,100,200],3,async offset=>({offset,data:await jsonGet(registry+'?task_verified=true&conformance=standard&limit=100&offset='+offset)}));
const records=new Map();for(const page of pages){for(const a of page.data?.agents??[]){if(a.conformance===true&&a.is_healthy===true&&a.task_conformance?.passed===true&&a.task_conformance?.category==='WORKING'&&a.wellKnownURI&&a.url){a.matchedTerms=terms.filter(term=>new RegExp(term.replace(' ','.?'),'i').test([a.name,a.description,...(a.skills??[]).flatMap(s=>[s.name,s.description,...(s.tags??[])])].join(' ')));records.set(a.id,a);}}}
const inspected=await mapLimit([...records.values()],20,async card=>{
  const record={...card,packageName:card.id,displayName:card.name,manifestUrl:card.wellKnownURI};if(card.executionEnabled===false||/NOT_AN_ACTIVE|DISCOVERY_METADATA_ONLY|DORMANT/i.test(String(card.interfaceStatus??'')))throw Error('not an active interface');
  const iface=selectInterface(card),skills=selectSkills(card).filter(skill=>unauthenticated(card,skill));if(!iface||!skills.length)throw Error('no public relevant read-only JSON-RPC skill');
  const endpoint=(await checkedUrl(iface.url)).href;if(new URL(endpoint).origin===origin)throw Error('self target');await checkedUrl(card.wellKnownURI);return {record,card,endpoint,tenant:iface.tenant??null,protocolVersion:iface.protocolVersion,skills};
});
const contacts=inspected.filter(x=>!x.error).flatMap(item=>item.skills.map(skill=>({...item,skill,score:relevance([item.record.displayName,item.record.description,item.card.description,item.record.matchedTerms.join(' '),skill.name,skill.description,...(skill.tags??[])].join(' '))}))).sort((a,b)=>b.score-a.score||a.endpoint.localeCompare(b.endpoint));
const uniqueContacts=new Map();for(const item of contacts){const key=item.endpoint+'\n'+String(item.skill.id??item.skill.name);if(!uniqueContacts.has(key))uniqueContacts.set(key,item);}
const targets=[],hostUse=new Map();for(const item of uniqueContacts.values()){const host=new URL(item.endpoint).hostname,n=hostUse.get(host)??0;if(n>=10)continue;targets.push(item);hostUse.set(host,n+1);if(targets.length===requested)break;}const uniqueHosts=new Set(targets.map(x=>new URL(x.endpoint).hostname));
const hostCounts=Object.fromEntries([...targets.reduce((m,x)=>m.set(new URL(x.endpoint).hostname,(m.get(new URL(x.endpoint).hostname)??0)+1),new Map())].sort((a,b)=>b[1]-a[1]));
const census={version:'WHP-CARRIER-CENSUS-v1',observed_at:new Date().toISOString(),registry,registry_evidence:'task_verified=true; conformance=standard; registry task_conformance category WORKING',query_terms:terms,search_errors:pages.filter(x=>x.error).map(x=>x.error),registry_records:records.size,active_relevant_contacts:uniqueContacts.size,selected_unique_hosts:uniqueHosts.size,selected_host_counts:hostCounts,selected_preview:targets.slice(0,20).map(x=>({name:x.record.displayName,host:new URL(x.endpoint).hostname,skill:x.skill.name,matched_terms:x.record.matchedTerms,score:x.score})),requested,selected:targets.length,selection:'Independently probed public A2A records whose most recent registry message/send task passed; current healthy and schema-conformant card; active unauthenticated JSON-RPC interface; distinct relevant read-only endpoint/skill pair; ranked by declared provenance/authority/high-stakes vocabulary. Multiple contacts to one host are permitted only for different published skills.'};
if(!execute){process.stdout.write(JSON.stringify(census,null,2)+'\n');if(targets.length<requested)process.exitCode=2;}
else{
  if(targets.length<requested)throw Error(`Only ${targets.length} legitimate unique targets available; no duplicate or inapplicable contacts added to reach ${requested}.`);
  const exactUtf8=await readFile(new URL('../evidence/public-v1/demonstration/TEST-standing-mark.json',import.meta.url),'utf8');if(sha256(exactUtf8)!==CARRIER_MARK.sha256)throw Error('carrier Mark bytes changed');
  const started=new Date().toISOString();
  const deliveries=await mapLimit(targets,4,async(target,index)=>{
    const {carrierId,body}=requestFor(target,index,exactUtf8),wire=JSON.stringify(body),at=new Date().toISOString(),begin=Date.now();
    try{const {response,bytes,url}=await boundedFetch(target.endpoint,{method:'POST',headers:{'content-type':'application/json',accept:'application/json','a2a-version':target.protocolVersion,'user-agent':`WHP-Standing-Carrier/1.0 (+${origin}/.well-known/agent-card.json)`},body:wire},262144);let parsed=null;try{parsed=JSON.parse(bytes.toString('utf8'));}catch{}
      return {carrier_id:carrierId,target:{registry_id:target.record.id,name:target.record.displayName,manifest_url:target.record.manifestUrl,endpoint:url,protocol_version:target.protocolVersion,skill_id:target.skill.id,skill_name:target.skill.name,matched_terms:target.record.matchedTerms,registry_task_checked_at:target.record.task_conformance?.checked_at,registry_task_response_ms:target.record.task_conformance?.response_ms},sent_at:at,duration_ms:Date.now()-begin,request_sha256:sha256(wire),request_bytes:Buffer.byteLength(wire),http_status:response.status,response_content_type:response.headers.get('content-type'),response_sha256:sha256(bytes),response_bytes:bytes.length,a2a_response:!!(parsed&&(parsed.result||parsed.error||parsed.task||parsed.message)),result_kind:parsed?.result?.task?'task':parsed?.result?.message?'message':parsed?.error?'error':null,task_state:parsed?.result?.status?.state??parsed?.result?.task?.status?.state??parsed?.task?.status?.state??null};
    }catch(e){return {carrier_id:carrierId,target:{registry_id:target.record.id,name:target.record.displayName,manifest_url:target.record.manifestUrl,endpoint:target.endpoint,protocol_version:target.protocolVersion,skill_id:target.skill.id,skill_name:target.skill.name,matched_terms:target.record.matchedTerms,registry_task_checked_at:target.record.task_conformance?.checked_at,registry_task_response_ms:target.record.task_conformance?.response_ms},sent_at:at,duration_ms:Date.now()-begin,request_sha256:sha256(wire),request_bytes:Buffer.byteLength(wire),network_error:String(e?.message??e)};}
  });
  const evidence={version:'WHP-CARRIER-FLEET-EXECUTION-v1',operator:'Wheeler Hubbell Publishing',started_at:started,completed_at:new Date().toISOString(),census,mark:{url:CARRIER_MARK.url,sha256:CARRIER_MARK.sha256,exact_bytes:Buffer.byteLength(exactUtf8)},counts:{carrier_instances:deliveries.length,http_responses:deliveries.filter(x=>Number.isInteger(x.http_status)).length,http_2xx:deliveries.filter(x=>x.http_status>=200&&x.http_status<300).length,a2a_responses:deliveries.filter(x=>x.a2a_response).length,network_errors:deliveries.filter(x=>x.network_error).length,payment_challenges:deliveries.filter(x=>x.http_status===402).length,auth_challenges:deliveries.filter(x=>x.http_status===401||x.http_status===403).length},claim_boundary:'Each record proves one bounded outbound request attempt and, where present, an HTTP/A2A response. It does not prove independent interpretation, relevance, endorsement, adoption, evaluation entry, payment or acquisition.',deliveries};
  await mkdir(new URL('../evidence/carriers/',import.meta.url),{recursive:true});const output=new URL('../evidence/carriers/fleet-100.json',import.meta.url);await writeFile(output,JSON.stringify(evidence,null,2)+'\n');process.stdout.write(JSON.stringify({output:output.pathname,counts:evidence.counts,census},null,2)+'\n');
}
