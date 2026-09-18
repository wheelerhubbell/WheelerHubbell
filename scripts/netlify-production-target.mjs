// The current production target only. No fingerprint is a module-level constant.
import {appendFile,readFile} from 'node:fs/promises';
import {demand,parseStrict,hashBytes} from '../src/canonical.mjs';
import {PROFILE_HASH} from '../src/profile.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
export const ORIGIN='https://wheeler-hubbell-publishing-standing-mark.netlify.app';
export const REPOSITORY='wheelerhubbell/WheelerHubbellPublishingStandingMark';
export const SITE_ID='0347a387-82b7-4b7f-b528-1024ad79b9e7';
export const COMMITMENTS=Object.freeze({profile:'d6296b9ea7a2c570c2c0ae98af8385d6f8edee1e869fb0ae9f553c90302303a7',contract:'ab76d9b6684ed2c2f26c21888d936d3f814dbe4f2357a9bf97fe538f513a200a',verifier:'dbca29eb4894d1ede33b4e909205f1a4430926444327babb724016bbc96a84e6'});
export async function verifySourceCommitments(){
 const m=parseStrict(await readFile(new URL('../public/verifier-manifest.json',import.meta.url),'utf8'));
 demand(PROFILE_HASH===COMMITMENTS.profile,'FROZEN_PROFILE_MISMATCH');
 demand(CONTRACT_HASH===COMMITMENTS.contract&&m.contract_hash===CONTRACT_HASH,'FROZEN_CONTRACT_MISMATCH');
 demand(VERIFIER_HASH===COMMITMENTS.verifier&&m.sha256===VERIFIER_HASH&&m.path==='/verification/'+VERIFIER_HASH+'.py','FROZEN_VERIFIER_MANIFEST_MISMATCH');
 demand(hashBytes(await readFile(new URL('../public'+m.path,import.meta.url)))===VERIFIER_HASH,'FROZEN_VERIFIER_BYTES_MISMATCH');
 return {...COMMITMENTS,verifier_bytes_checked:true,contract_regenerated:false};
}
export async function api(path,method='GET',body){
 demand(process.env.NETLIFY_AUTH_TOKEN,'NETLIFY_AUTH_TOKEN_REQUIRED',503);
 const r=await fetch('https://api.netlify.com/api/v1'+path,{method,headers:{Authorization:'Bearer '+process.env.NETLIFY_AUTH_TOKEN,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(60000)});
 demand(r.ok,'NETLIFY_'+method+'_'+r.status,503);return r.status===204?null:r.json();
}
export const value=(e,c='production')=>e?.values?.find(v=>v.context===c)?.value??(c==='production'?e?.values?.find(v=>v.context==='all')?.value:undefined);
export const prefix=s=>{demand(s?.account_id,'NETLIFY_ACCOUNT_ID_REQUIRED');return '/accounts/'+s.account_id+'/env';};
export async function variables(site){return api(prefix(site)+'?site_id='+site.id);}
export async function variable(site,key){
 try{return await api(prefix(site)+'/'+encodeURIComponent(key)+'?site_id='+site.id);}catch(e){if(e.code==='NETLIFY_GET_404')return null;throw e;}
}
export function assertTarget(site){demand(site.id===SITE_ID&&site.ssl_url===ORIGIN,'PRODUCTION_WRITE_TARGET_MISMATCH');}
export async function createVariable(site,key,data,context='production'){
 assertTarget(site);demand(typeof data==='string'&&Buffer.byteLength(data)<=5000,'ENVIRONMENT_VALUE_SIZE_LIMIT');
 await api(prefix(site)+'?site_id='+site.id,'POST',[{key,values:[{context,value:data}]}]);
}
export async function put(site,key,data,context='production'){
 assertTarget(site);demand(typeof data==='string'&&Buffer.byteLength(data)<=5000,'ENVIRONMENT_VALUE_SIZE_LIMIT');
 const prior=await variable(site,key);
 if(prior?.values?.length===1&&prior.values[0].context===context&&prior.values[0].value===data)return;
 const body={key,values:[{context,value:data}]};
 await api(prefix(site)+(prior?'/'+encodeURIComponent(key):'')+'?site_id='+site.id,prior?'PUT':'POST',prior?body:[body]);
}
async function resolveAccountId(site){
 if(site.account_id)return site.account_id;
 if(site.account_slug){
  const account=await api('/accounts/'+encodeURIComponent(site.account_slug));
  demand(account?.id,'NETLIFY_ACCOUNT_ID_REQUIRED');return account.id;
 }
 const accounts=await api('/accounts');demand(Array.isArray(accounts)&&accounts.length,'NETLIFY_ACCOUNTS_REQUIRED');
 const matches=[];
 for(const account of accounts){
  const slug=account?.slug??account?.id;if(!slug)continue;
  let sites;try{sites=await api('/'+encodeURIComponent(slug)+'/sites?per_page=100');}catch(e){if(e.code==='NETLIFY_GET_403'||e.code==='NETLIFY_GET_404')continue;throw e;}
  if(Array.isArray(sites)&&sites.some(x=>x?.id===site.id))matches.push(account.id??slug);
 }
 demand(matches.length===1,'NETLIFY_SITE_ACCOUNT_REQUIRED');return matches[0];
}
export async function target(){
 const s=await api('/sites/'+SITE_ID);assertTarget(s);
 const repo=s.build_settings??s.repo??{};
 const path=(repo.repo_path??repo.repo_url??'').replace(/^https?:\/\/github.com\//,'').replace(/\.git$/,'');
 if(path)demand(path===REPOSITORY,'NETLIFY_REPOSITORY_CUTOVER_REQUIRED',503);
 if(repo.repo_branch)demand(repo.repo_branch==='main','NETLIFY_REPOSITORY_CUTOVER_REQUIRED',503);
 return {...s,account_id:await resolveAccountId(s)};
}
export async function exportTarget(site){if(process.env.GITHUB_ENV)await appendFile(process.env.GITHUB_ENV,'NETLIFY_SITE_ID='+site.id+'\nWHP_ORIGIN='+ORIGIN+'\n');}
