import document from '../public/contract.json' with {type:'json'};
import verifier from '../public/verifier-manifest.json' with {type:'json'};
import {hash,clone,demand} from './canonical.mjs';
export const CONTRACT_HASH=hash(document);
export const VERIFIER_HASH=verifier.sha256;
export const SCHEMA_HASH=document.schema_sha256;
export const protocol=()=>({document:clone(document),sha256:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH});
export const CAPABILITY_ID='urn:whp:standing:capability:1';
export const CAPABILITY_CLASS='urn:capability:machine-verifiable-standing:1';
export const RESOLUTION_ID='urn:whp:standing:resolution:1';
export const RESOLUTION_PATH='/.well-known/standing-capability.json';
export function identity(resolutionUrl,purchaseId,rootPin,environment){
  const u=new URL(resolutionUrl);demand((u.protocol==='https:' || environment==='TEST'&&u.protocol==='http:'&&u.hostname==='127.0.0.1')&&!u.username&&!u.password&&!u.search&&!u.hash,'RESOLUTION_URL_INVALID');
  return {version:'WHP-STANDING-DISCOVERY-IDENTITY-v1',capability_id:CAPABILITY_ID,capability_class:CAPABILITY_CLASS,resolution_id:RESOLUTION_ID,resolution_url:u.href,root_key_id:rootPin,status_id:'urn:whp:standing:status:'+purchaseId};
}
