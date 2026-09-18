// Runs the same generic consumer twice with real preauthorized wallet runtimes.
// No keys, budgets, authority grants, URLs or root admissions are invented here.
import {readFile,writeFile,mkdir,copyFile,symlink} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {spawn} from 'node:child_process';
import {hashBytes,demand} from '../src/canonical.mjs';
import {releaseSource} from './release-source.mjs';
const run=(executable,args,options)=>new Promise((res,rej)=>{const p=spawn(executable,args,{...options,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('error',rej);p.on('close',code=>res({code,stdout,stderr}));});
try{
  const [aFile,bFile,directory]=process.argv.slice(2);demand(aFile&&bFile&&directory,'A_INPUT_B_INPUT_DURABLE_DIRECTORY_REQUIRED');
  const [a,b]=await Promise.all([aFile,bFile].map(p=>readFile(p,'utf8').then(JSON.parse)));
  demand(!a.wallet.test_key&&!b.wallet.test_key&&a.catalog_url&&!b.catalog_url&&!b.interaction,'LIVE_COLD_INPUTS_REQUIRED');
  demand(process.env.GENERIC_OWNER_WALLET_A&&process.env.GENERIC_OWNER_WALLET_B&&process.env.WHP_RELEASE_ROOT_PIN&&process.env.WHP_RELEASE_RPC_URL,'EXISTING_OWNER_WALLETS_AND_TRUST_POLICY_REQUIRED');
  const out=resolve(directory);await mkdir(out,{recursive:true,mode:0o700});
  const candidate=await releaseSource();
  async function consume(name,input,wallet){
    const cwd=join(out,name);await mkdir(cwd,{recursive:true,mode:0o700});
    await copyFile('scripts/cold-purchaser.mjs',join(cwd,'consumer.mjs'));await writeFile(join(cwd,'input.json'),JSON.stringify(input),{mode:0o600});
    const modules=resolve('node_modules');try{await symlink(modules,join(cwd,'node_modules'));}catch(e){if(e.code!=='EEXIST')throw e;}
    const modulePath=resolve(wallet),args=['--permission','--allow-child-process','--allow-fs-read='+cwd,'--allow-fs-write='+cwd,'--allow-fs-read='+modules,'--allow-fs-read='+dirname(modulePath),join(cwd,'consumer.mjs'),join(cwd,'input.json')];
    const child=await run(process.execPath,args,{cwd,env:{PATH:process.env.PATH,GENERIC_PYTHON:process.env.WHP_TEST_PYTHON??'python3',GENERIC_SANDBOX:resolve('scripts/public-artifact-sandbox.py'),GENERIC_OWNER_WALLET_MODULE:modulePath}});
    const report=JSON.parse(child.stdout);await writeFile(join(out,name+'.consumer.json'),JSON.stringify(report,null,2)+'\n');
    if(report.pending){console.log(JSON.stringify({complete:false,pending:true,agent:name,purchase_id:report.purchase_id,additional_charge:false,durable_directory:out}));process.exit(2);}
    demand(child.code===0&&report.acquired===true&&report.environment==='LIVE','LIVE_'+name+'_ACQUISITION_FAILED:'+report.error);
    for(const file of ['mark','registry'])await copyFile(join(cwd,file+'.json'),join(out,name+'.'+file+'.json'));
    return report;
  }
  const ra=await consume('A',a,process.env.GENERIC_OWNER_WALLET_A),markA=await readFile(join(out,'A.mark.json'));
  const interaction={jsonrpc:'2.0',id:1,result:{content:[{type:'text',text:'Ordinary machine handoff with signed provenance metadata.'}],_meta:{signed_artifacts:[markA.toString('base64')]}}};
  const rb=await consume('B',{...b,interaction},process.env.GENERIC_OWNER_WALLET_B),markB=await readFile(join(out,'B.mark.json'));
  demand((await releaseSource()).sha256===candidate.sha256,'RELEASE_SOURCE_CHANGED_DURING_EXECUTION');
  const record=(r,bytes)=>({mark_sha256:hashBytes(bytes),wallet_calls:r.wallet_calls,clean_environment:true,provider_prior_configuration:false,whp_client_installed:false,trace:r.trace,milestones:r.milestones,http_statuses:r.trace.filter(x=>x.method==='POST').map(x=>x.status)});
  const receipt={version:'WHP-LIVE-CHAIN-EXECUTION-v1',environment:'LIVE',consumer_sha256:hashBytes(await readFile('scripts/cold-purchaser.mjs')),service_candidate:candidate,source_binding:'Captured orchestrator worktree at execution; not an attestation of remote deployed bytes.',a:record(ra,markA),b:{...record(rb,markB),encountered_mark_sha256:rb.encountered_admission.mark_sha256,encountered_admission:rb.encountered_admission,provider_url_source:'ENCOUNTERED_MARK',relevance_source:'OWN_TASK'}};
  await writeFile(join(out,'execution.json'),JSON.stringify(receipt,null,2)+'\n');
  const gate=await run(process.execPath,['scripts/check-live-chain.mjs'],{cwd:process.cwd(),env:{...process.env,WHP_LIVE_CHAIN_DIR:out}});process.stdout.write(gate.stdout);process.stderr.write(gate.stderr);process.exitCode=gate.code;
}catch(e){console.error(JSON.stringify({complete:false,error:e.code??e.message}));process.exitCode=1;}
