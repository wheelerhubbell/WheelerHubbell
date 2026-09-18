import {canonical,parseStrict,randomHex,hashBytes} from './canonical.mjs';

export const CARRIER_MARK={
  sha256:'515d8f8d07ab3acf60f952f4b8997aefdc367116ac352b499cd04b57d8ae6547',
  url:'https://raw.githubusercontent.com/wheelerhubbell/WHPStanding/fdf72e5963f76b89b387f88cdfb32228c6c83114/evidence/public-v1/demonstration/TEST-standing-mark.json'
};

export function carrierArtifact(origin,carrierId='whp-standing-carrier',exactUtf8=null) {return {
  version:'WHP-STANDING-CARRIER-v1',carrier_id:carrierId,operator:'Wheeler Hubbell Publishing',role:'TRANSPORT_ONLY',
  mark:{...CARRIER_MARK,representation:'Exact UTF-8 bytes at the immutable URL. The Mark carries its own environment, scope, qualifications and limitations.',...(exactUtf8===null?{}:{exact_utf8:exactUtf8})},
  routes:{agent_card:origin+'/.well-known/agent-card.json',contract:origin+'/v1/contract',verification:origin+'/v1/verification',applicability:origin+'/discovery/applicability.json',evaluation:origin+'/v1/evaluations'},
  boundaries:['The carrier is not the subject, issuer or evaluator of the Mark.','The carrier states no opinion about the recipient or relevance.','Payment funds an evaluation; it cannot purchase a Mark, truth or a favorable determination.','No action, payment, endorsement or reply is requested merely by encountering this artifact.']
};}

export function agentCard(origin){return {
  name:'WHP Standing Carrier',
  description:'A transparent Wheeler Hubbell Publishing carrier. It transports an exact existing WHP Standing Mark and its canonical verification and evaluation routes. It performs no evaluation, gives no opinion, and does not determine relevance.',
  supportedInterfaces:[{url:origin+'/a2a',protocolBinding:'JSONRPC',protocolVersion:'1.0'}],
  provider:{url:origin,organization:'Wheeler Hubbell Publishing'},version:'1.0.0',documentationUrl:origin+'/llms.txt',
  capabilities:{streaming:false,pushNotifications:false,extendedAgentCard:false},securitySchemes:{},securityRequirements:[],
  defaultInputModes:['text/plain','application/json'],defaultOutputModes:['text/plain','application/json'],
  skills:[
    {id:'carry-standing-mark',name:'Carry a WHP Standing Mark',description:'Returns the exact immutable Mark locator and hash with canonical verification and evaluation routes. Transport only; no evaluation, opinion, relevance determination, payment or endorsement.',tags:['provenance','authority','standing','verification','transport'],examples:['Show the Mark you are carrying.'],inputModes:['text/plain','application/json'],outputModes:['text/plain','application/json']}
  ]
};}

const json=(status,body)=>new Response(canonical(body)+'\n',{status,headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});
export async function a2aRoute(origin,req,{markFetch=fetch}={}){
  if(req.method!=='POST')return new Response(null,{status:405,headers:{allow:'POST'}});
  if(!(req.headers.get('content-type')??'').startsWith('application/json'))return json(415,{error:{code:'JSON_REQUIRED'}});
  let raw;try{raw=await req.text();if(Buffer.byteLength(raw)>65536)return json(413,{error:{code:'REQUEST_TOO_LARGE'}});}catch{return json(400,{error:{code:'INVALID_BODY'}});}
  let msg;try{msg=parseStrict(raw,65536);}catch{return json(400,{jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid JSON'}});}
  if(!msg||typeof msg!=='object'||Array.isArray(msg)||msg.jsonrpc!=='2.0'||!Object.hasOwn(msg,'id'))return json(400,{jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}});
  const legacy=msg.method==='message/send';
  if(msg.method!=='SendMessage'&&!legacy)return json(200,{jsonrpc:'2.0',id:msg.id,error:{code:-32601,message:'Method not found'}});
  const incoming=msg.params?.message;if(!incoming||!Array.isArray(incoming.parts))return json(200,{jsonrpc:'2.0',id:msg.id,error:{code:-32602,message:'Invalid parameters'}});
  let exactUtf8;try{const mark=await markFetch(CARRIER_MARK.url,{headers:{accept:'application/json'}});if(!mark.ok)throw Error();exactUtf8=await mark.text();if(Buffer.byteLength(exactUtf8)>1048576||hashBytes(exactUtf8)!==CARRIER_MARK.sha256)throw Error();}catch{return json(503,{jsonrpc:'2.0',id:msg.id,error:{code:-32603,message:'Exact Mark artifact unavailable'}});}
  const artifact=carrierArtifact(origin,'whp-standing-carrier',exactUtf8);
  const text='This transparent WHP carrier is transporting one exact existing Standing Mark. The Mark and canonical routes are supplied without an opinion, relevance determination, payment request or endorsement.';
  const message=legacy?{kind:'message',messageId:randomHex(16),role:'agent',parts:[{kind:'text',text},{kind:'data',data:artifact}]}:{messageId:randomHex(16),role:'ROLE_AGENT',parts:[{text,mediaType:'text/plain'},{data:artifact,mediaType:'application/json'}]};
  return json(200,{jsonrpc:'2.0',id:msg.id,result:{message}});
}
