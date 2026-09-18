import {runtimeFromEnvironment} from '../../src/runtime.mjs';
import {exposureLinks} from '../../src/exposure.mjs';
import {publicMachineRoute} from '../../src/public-machine.mjs';
let service;
export default async function handler(request){
  try{service??=runtimeFromEnvironment().catch(e=>{service=null;throw e;});const current=await service;const direct=await publicMachineRoute(current,request);const result=direct??await current.handle(request);const headers=new Headers(result.headers);headers.set('link',exposureLinks(current.origin));return new Response(result.body,{status:result.status,statusText:result.statusText,headers});}
  catch{return new Response('{"error":{"code":"SERVICE_UNAVAILABLE"}}',{status:503,headers:{'content-type':'application/json','cache-control':'no-store'}});}
}
export const config={path:['/','/v1/*','/.well-known/whp-standing.json','/.well-known/standing-capability.json','/.well-known/agent-card.json','/.well-known/agent.json','/.well-known/x402','/openapi.json','/discovery/*','/verification/*','/examples/*','/.well-known/api-catalog','/healthz','/schemas/*','/a2a','/mcp','/server.json','/robots.txt','/sitemap.xml','/llms.txt']};
