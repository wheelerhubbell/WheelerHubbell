// Public boundary verification only. No wallet, buyer impersonation, or settlement.
import {generateKeyPairSync} from 'node:crypto';
import {mkdir,writeFile} from 'node:fs/promises';
import {canonical,hash,hashBytes,publicDer,seal,encode,clone,demand,openSeal,keyId} from '../src/canonical.mjs';
import {clientProof} from '../src/service.mjs';
import {validateSubmission} from '../src/validation.mjs';
import {validateTrust,authorize} from '../src/authority.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {checkPublicService} from './check-public-service.mjs';
const origin='https://wheelerhubbellpublishingstandingmark.netlify.app',pin=process.env.WHP_ROOT_PIN;
const trace=[],report={checked_at:new Date().toISOString(),origin,payment_authorizations_created:0,settlement_calls:0,SOLD:false,ISSUED:false,'PROPAGATION-PROVEN':false};
async function req(url,options){const r=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(30000)});const body=await r.text();trace.push({url,method:options?.method??'GET',status:r.status,sha256:hashBytes(body)});return {r,body,json:()=>JSON.parse(body)};}
try{
 Object.assign(report,await checkPublicService(origin,pin));
 const need={object:{id:'public-boundary-diagnostic',action:'INFORM'},requirement:'Machine-verifiable standing under explicit authority and bounds.',provider_catalog:origin+'/.well-known/api-catalog'};
 const catalog=(await req(need.provider_catalog)).json();
 const entry=catalog.linkset.find(e=>e['service-meta']&&e['service-desc']);demand(entry,'PROVIDER_METADATA_MISSING');
 const contract=(await req(entry['service-meta'][0].href)).json();demand(contract.capability===need.requirement,'CAPABILITY_MISMATCH');
 const discovery=(await req(contract.discovery_url)).json();demand(discovery.root_pin===pin,'ROOT_MISMATCH');
 const resolved=(await req(origin+'/.well-known/standing-capability.json')).json();
 const trust=validateTrust(discovery.trust_bundle,pin,Math.floor(Date.now()/1000));
 authorize(resolved,'WHP-CAPABILITY-RESOLUTION-v1','DISCOVERY',resolved.payload.authority_context,trust);
 demand(resolved.payload.service_origin===origin&&resolved.payload.environment==='LIVE'&&trust.profile.contract_hash===CONTRACT_HASH&&trust.profile.verifier_sha256===VERIFIER_HASH,'CURRENT_PRODUCTION_RESOLUTION_MISMATCH');
 const providers=(await req(origin+'/discovery/provider-index.json')).json();
 demand(resolved.payload.provider_discovery.url===origin+'/discovery/provider-index.json'&&providers.providers.some(p=>p.capability_class==='urn:capability:machine-verifiable-standing:1'&&p.resolution_url===origin+'/.well-known/standing-capability.json'),'PRODUCTION_CAPABILITY_DISCOVERY_MISSING');
 report.signed_production_resolution_verified=true;report.vendor_neutral_capability_surface_available=true;
 const profile=(await req(contract.profile.url)).json();demand(hash(profile.profile)===contract.profile.sha256,'PROFILE_HASH_MISMATCH');
 await req(contract.purchase.input_schema);
 const key=generateKeyPairSync('ed25519').privateKey,at=Math.floor(Date.now()/1000);
 const cert=discovery.issuer_certificate.payload;
 const bounds={scope:cert.scopes[0],jurisdiction:cert.jurisdictions[0],valid_from:at-1,valid_until:at+300};
 const node={id:need.object.id,version:'1',content:{statement:'Public payment-boundary diagnostic; no purchase or standing claim.'},locator:'urn:whp:diagnostic:public-boundary',epistemic_status:'REPORT',qualifiers:['Diagnostic only; not admitted SOURCE authority.'],unknowns:[],operations:['INFORM'],...bounds,status:'ACTIVE',prior_hash:null};
 const s={version:'WHP-STANDING-SUBMISSION-v1',client_reference:'public_probe_'+process.env.GITHUB_RUN_ID,buyer_key:publicDer(key),profile:{id:contract.profile.id,version:contract.profile.version,sha256:contract.profile.sha256},object:{id:node.id,version:node.version,root:hash(node)},bounds,requested_operation:'INFORM',nodes:[seal('WHP-SOURCE-ATTESTATION-v1',node,key)],transitions:[]};
 validateSubmission(s);const raw=canonical(s),path=new URL(contract.purchase.url).pathname;
 async function submit(payment){const headers={'content-type':'application/json','whp-client-proof':clientProof(key,'POST',path,raw,Math.floor(Date.now()/1000))};if(payment)headers['payment-signature']=encode(payment);return req(contract.purchase.url,{method:'POST',headers,body:raw});}
 const q=await submit();demand(q.r.status===402&&q.r.headers.get('payment-required'),'PUBLIC_PAYMENT_BOUNDARY_NOT_REACHED');const terms=q.json(),quote=terms.extensions['whp-standing'].info.quote;
 openSeal(quote,'WHP-STANDING-QUOTE-v1',cert.public_key);demand(quote.protected.key_id===keyId(cert.public_key)&&quote.payload.environment==='LIVE','LIVE_QUOTE_SIGNATURE_REQUIRED');
 demand(canonical(terms.accepts[0])===canonical(contract.purchase.requirements),'PAYMENT_TERMS_MISMATCH');
 const decoded=JSON.parse(Buffer.from(q.r.headers.get('payment-required'),'base64').toString());demand(canonical(decoded)===canonical(terms),'PAYMENT_HEADER_BODY_MISMATCH');
 report.public_payment_status=402;report.public_quote=quote;report.need_test={input:need,provider_catalog_seed_supplied:true,provider_discovery_verified:true,profile_contract_verified:true,public_payment_boundary_verified:true};
 report.inherited_wrong_term_tests_not_rerun=true;
 const again=await submit();demand(again.r.status===402&&canonical(again.json().extensions['whp-standing'].info.quote)===canonical(quote),'DURABLE_QUOTE_RETRIEVAL_FAILED');
 report.durable_quote_retrieval_verified=true;
 report.mark_test={state:'NOT_EXECUTED',reason:'No genuine paid LIVE Mark exists. No synthetic LIVE Mark was created.'};
 report.state='VERIFIED';report.trace=trace;
}catch(e){report.failure=e.code??e.message;report.trace=trace;process.exitCode=1;}
await mkdir('evidence/public-service',{recursive:true});await writeFile('evidence/public-service/public-boundary.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
