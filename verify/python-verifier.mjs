import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const run=promisify(execFile);
export function pythonVerifier({rootPin,allowTest=false,rpcUrl,python='python3'}){
  return async(bytes,registry,at)=>{
    const dir=await mkdtemp(join(tmpdir(),'whp-verifier-'));
    try{const mark=join(dir,'result.json'),status=join(dir,'registry.json');await writeFile(mark,bytes,{mode:0o600});await writeFile(status,registry,{mode:0o600});
      const args=[fileURLToPath(new URL('./verify_mark.py',import.meta.url)),mark,'--root-pin',rootPin,'--registry',status,'--at',String(at)];
      if(allowTest)args.push('--allow-test');if(rpcUrl)args.push('--rpc',rpcUrl);
      const {stdout}=await run(python,args,{timeout:60000,maxBuffer:1048576});return JSON.parse(stdout);
    }finally{await rm(dir,{recursive:true,force:true});}
  };
}
