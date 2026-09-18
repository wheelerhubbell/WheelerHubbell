// Read-only preflight. The repository's committed signed authority is the activation authority.
import {readFile} from 'node:fs/promises';
import {validateTrust,issuerAuthority} from '../src/authority.mjs';
import {parseStrict,demand} from '../src/canonical.mjs';
import {PROFILE_HASH} from '../src/profile.mjs';
import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
try{
  const published=parseStrict(await readFile(new URL('../public/authority/root.json',import.meta.url),'utf8'),1048576);
  const bundle=published.trust_bundle,pin=published.root_pin;
  demand(bundle&&pin,'MATCHING_AUTHORITY_REQUIRED');
  const trust=validateTrust(bundle,pin,Math.floor(Date.now()/1000));demand(trust.profile.environment==='LIVE','LIVE_AUTHORITY_REQUIRED');
  const issuer=[...trust.keys.entries()].find(([,c])=>c.roles.includes('ISSUER')&&c.roles.includes('DISCOVERY')&&c.roles.includes('REGISTRY'));
  demand(issuer,'ISSUER_REQUIRED');issuerAuthority(issuer[0],'https://github.com/independent-controller/records','namespace-control',trust);
  console.log(JSON.stringify({activation_authority_verified:true,root_pin:pin,issuer_key_id:issuer[0],profile:PROFILE_HASH,contract:CONTRACT_HASH,verifier:VERIFIER_HASH,production_completion:false,authority_source:'repository'}));
}catch(e){console.error(JSON.stringify({activation_authority_verified:false,error:e.code??e.message,production_completion:false}));process.exitCode=1;}
