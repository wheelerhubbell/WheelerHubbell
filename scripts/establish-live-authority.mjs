// Manual entrypoint for the already-ratified v1.1 WHP authority. No key establishment.
import {mkdir,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {syncV11Authority} from './sync-v11-authority.mjs';

export async function establishProduction(){
  const sync=await syncV11Authority();
  const report={checked_at:new Date().toISOString(),state:'EXISTING_V11_AUTHORITY_SYNCHRONIZED',source_commit:process.env.GITHUB_SHA??null,...sync,signing_identity_changed:false,previous_trust_identity_continued:true,public_cutover_completed:false,live_mark_issued:false};
  await mkdir('evidence/live-authority',{recursive:true});
  await writeFile('evidence/live-authority/fresh-key-establishment.json',JSON.stringify(report,null,2)+'\n');
  return report;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{console.log(JSON.stringify(await establishProduction()));}
  catch(e){console.error('V11_AUTHORITY_SYNC_STOPPED',e.code??'SAFE_INTERNAL_FAILURE');process.exitCode=1;}
}
