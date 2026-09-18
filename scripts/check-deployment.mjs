// Provider-neutral deployment preflight. Public trust/payment configuration is source-owned.
// A host supplies only private/infrastructure inputs; this check performs no payment.
import {runtimeFromEnvironment} from '../src/runtime.mjs';
const env=process.env;
const missing=[];
if(!env.WHP_ISSUER_PRIVATE_KEY)missing.push('WHP_ISSUER_PRIVATE_KEY');
if(env.WHP_USE_NETLIFY_DATABASE!=='true'&&!env.DATABASE_URL&&!env.NETLIFY_DB_URL)missing.push('DATABASE_URL (or provider database adapter)');
let service;
try{
  if(missing.length){
    console.error(JSON.stringify({deployment_ready:false,error:'RUNTIME_INFRASTRUCTURE_MISSING',missing}));
    process.exitCode=1;
  }else{
    service=await runtimeFromEnvironment(env);
    await service.store.initialize();
    await service.store.get('__deployment_readiness_probe__');
    console.log(JSON.stringify({deployment_configuration_verified:true,database_schema_initialized:true,origin:service.origin,
      root_pin:service.rootPin,issuer_key_id:service.keyId,payment_executed:false,production_completion:false,
      public_authority_source:'repository',payment_configuration_source:'repository'}));
  }
}catch(e){
  const code=typeof e.code==='string'&&/^[A-Z0-9_]{1,100}$/.test(e.code)?e.code:'DEPLOYMENT_CONFIGURATION_OR_DATABASE_INVALID';
  console.error(JSON.stringify({deployment_ready:false,error:code,production_completion:false}));process.exitCode=1;
}finally{if(service)await service.store.close();}
