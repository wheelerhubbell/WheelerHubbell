// No provider credentials, key generation, database access, quotations, payments, or test campaigns.
import {mkdir,writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {hashBytes} from '../src/canonical.mjs';
import {ORIGIN,COMMITMENTS,verifySourceCommitments} from './netlify-production-target.mjs';
const report={checked_at:new Date().toISOString(),source_commit:process.env.GITHUB_SHA??null,production_keys_generated:false,private_configuration_accessed:false,database_accessed:false,quotation_created:false,payment_executed:false,live_mark_issued:false,retained_test_campaigns_rerun:false};
await mkdir('artifacts',{recursive:true});
try{
 report.commitments=await verifySourceCommitments();
 const files=['netlify-production-target.mjs','production-authority-v2.mjs','establish-live-authority.mjs','configure-production.mjs','refresh-live-status.mjs','observe-authority-deployment.mjs'];
 for(const file of files){execFileSync(process.execPath,['--check','scripts/'+file],{stdio:'pipe'});await import('./'+file);}
 report.module_syntax_and_imports={passed:true,files};report.public_responses=[];
 for(const path of ['/healthz','/.well-known/whp-standing.json','/.well-known/standing-capability.json','/verification/'+COMMITMENTS.verifier+'.py']){
  try{const r=await fetch(ORIGIN+path,{redirect:'error',signal:AbortSignal.timeout(20000)});const raw=await r.text();report.public_responses.push({path,service_response:true,status:r.status,response_sha256:hashBytes(raw),verifier_bytes_match:path.endsWith('.py')?hashBytes(raw)===COMMITMENTS.verifier:null});}
  catch(e){report.public_responses.push({path,service_response:false,tool_or_runner_connection_error:e.cause?.code??e.code??e.name});}
 }
}catch(e){report.failure=e.code??e.name;process.exitCode=1;}
await writeFile('artifacts/repair-boundaries.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
