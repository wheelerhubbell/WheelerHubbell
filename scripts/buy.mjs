// Explicit invocation only. This command uses the owner's pre-authorized wallet provider.
// No embedded wallet, default spending allowance, or automatic authority grant exists.
import {readFile,writeFile} from 'node:fs/promises';import {resolve} from 'node:path';import {pathToFileURL} from 'node:url';
import {StandingBuyer,Eip1193Signer} from '../src/buyer.mjs';import {BuyerJournal} from '../src/buyer-journal.mjs';import {pythonVerifier} from '../verify/python-verifier.mjs';import {parseStrict,demand} from '../src/canonical.mjs';
const [policyFile,submissionFile,providerFile,journalFile,outputFile]=process.argv.slice(2);
demand(policyFile&&submissionFile&&providerFile&&journalFile&&outputFile,'Usage: node scripts/buy.mjs POLICY.json SUBMISSION.json OWNER_PROVIDER.mjs JOURNAL.sqlite OUTPUT.json');
const policy=parseStrict(await readFile(policyFile,'utf8')),submission=parseStrict(await readFile(submissionFile,'utf8'));
demand(policy.environment==='LIVE','LIVE_BUYER_CLI_REQUIRES_LIVE_POLICY');demand(process.env.WHP_BUYER_RPC_URL?.startsWith('https://'),'WHP_BUYER_RPC_URL_REQUIRED');
const provider=(await import(pathToFileURL(resolve(providerFile)).href)).default,journal=new BuyerJournal(journalFile);
const buyer=new StandingBuyer({policy,paymentSigner:new Eip1193Signer(provider),journal,
  verifyResult:pythonVerifier({rootPin:policy.root_pin,rpcUrl:process.env.WHP_BUYER_RPC_URL})});
const deadline=Date.now()+Number(process.env.WHP_BUYER_MAX_WAIT_SECONDS??1800)*1000;
try{for(;;){let result;try{result=await buyer.purchase(submission);}catch(e){
    // Transport and service interruptions do not mint a new transaction identity.
    // Policy/authority refusals stop rather than retrying around them.
    if(e.code||Date.now()>=deadline)throw e;await new Promise(r=>setTimeout(r,30000));continue;}
    if(result.state==='VERIFIED'){await writeFile(outputFile,result.result_bytes,{mode:0o600,flag:'wx'});console.log(JSON.stringify(result.verification,null,2));break;}
    if(Date.now()>=deadline){console.log(JSON.stringify({...result,message:'Purchase remains durable in the same journal. Resume this command with the same files; do not authorize a replacement purchase.'},null,2));process.exitCode=2;break;}
    await new Promise(r=>setTimeout(r,30000));
}}finally{journal.close();}
