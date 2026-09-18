// Scheduled entrypoint for the already-ratified v1.1 WHP authority. No key establishment.
import {pathToFileURL} from 'node:url';
import {syncV11Authority} from './sync-v11-authority.mjs';

export async function refreshStatus(){
  const result=await syncV11Authority();
  return {changed:result.status_renewed||result.production_configuration_changed,...result,deployed_runtime_refresh_verified:false};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{console.log(JSON.stringify(await refreshStatus()));}
  catch(e){console.error('STATUS_REFRESH_STOPPED',e.code??'SAFE_INTERNAL_FAILURE');process.exitCode=1;}
}
