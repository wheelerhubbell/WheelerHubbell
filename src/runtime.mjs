import {createPrivateKey} from 'node:crypto';
import {demand} from './canonical.mjs';
import {postgresStore} from './store.mjs';
import {EvmRail} from './payment.mjs';
import {StandingService} from './service.mjs';
import {validateTrust,issuerAuthority} from './authority.mjs';
import {keyId,publicDer} from './canonical.mjs';
import {livePaymentDestination,bazaar} from './discovery.mjs';
import {runtimeDefaults,PRODUCTION_PAYMENT_REQUIREMENTS} from './production-config.mjs';
import publishedAuthority from '../public/authority/root.json' with {type:'json'};

export async function runtimeFromEnvironment(env=process.env){
  const defaults=runtimeDefaults(env);
  const origin=defaults.origin,rootPin=publishedAuthority.root_pin,trustBundle=publishedAuthority.trust_bundle,requirements=PRODUCTION_PAYMENT_REQUIREMENTS;
  demand(origin,'CONFIG_WHP_ORIGIN_REQUIRED',503);
  demand(env.WHP_ISSUER_PRIVATE_KEY,'CONFIG_WHP_ISSUER_PRIVATE_KEY_REQUIRED',503);
  validateTrust(trustBundle,rootPin,Math.floor(Date.now()/1000));livePaymentDestination(requirements);
  demand(trustBundle.profile_authorization.payload.environment==='LIVE','PRODUCTION_REQUIRES_LIVE_AUTHORITY',503);
  const privateKey=createPrivateKey(env.WHP_ISSUER_PRIVATE_KEY),issuerKeyId=keyId(publicDer(privateKey));
  issuerAuthority(issuerKeyId,'whp-standing-structured-passage','protocol-structural-assessment-only',validateTrust(trustBundle,rootPin,Math.floor(Date.now()/1000)));
  const rail=new EvmRail({facilitator_url:defaults.facilitatorUrl,rpc_url:defaults.rpcUrl,network:requirements.network,discovery_extensions:{bazaar:bazaar({origin})}});
  const connectionString=env.WHP_USE_NETLIFY_DATABASE==='true'?(await import('@netlify/database')).getConnectionString():env.DATABASE_URL??env.NETLIFY_DB_URL;
  demand(connectionString,'CONFIG_DATABASE_REQUIRED',503);
  const store=await postgresStore(connectionString);
  try{return new StandingService({store,rail,privateKey,trustBundle,rootPin,origin,resolutionUrl:env.WHP_RESOLUTION_URL??origin+'/.well-known/standing-capability.json',catalogUrl:env.WHP_CAPABILITY_CATALOG_URL??origin+'/discovery/provider-index.json',requirements});}catch(e){await store.close();throw e;}
}
