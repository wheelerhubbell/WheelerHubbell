import { demand, exact, hash, canonical, Fault } from './canonical.mjs';
import { keccak } from './keccak.mjs';
export const EVM_ADDRESS=/^0x[0-9a-fA-F]{40}$/;
export const HEX32=/^0x[0-9a-fA-F]{64}$/;
export const TRANSFER_TOPIC=keccak('Transfer(address,address,uint256)');
export const AUTH_TOPIC=keccak('AuthorizationUsed(address,bytes32)');
export const TRANSFER_SELECTOR=keccak('transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)').slice(0,10);
export const wordAddress=a=>'0x'+'0'.repeat(24)+a.slice(2).toLowerCase();
export const authorizationNonce=quote=>'0x'+hash({domain:'WHP-STANDING-PURCHASE-BINDING-v1',quote:quote.payload});
const decimal=s=>typeof s==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(s)&&BigInt(s)<2n**256n;
export function validateRequirements(r){
  exact(r,['scheme','network','amount','asset','payTo','maxTimeoutSeconds','extra']);
  exact(r.extra,['assetTransferMethod','paymentFlow','name','version']);
  demand(r.scheme==='exact'&&/^eip155:[1-9][0-9]*$/.test(r.network)&&EVM_ADDRESS.test(r.asset)&&EVM_ADDRESS.test(r.payTo),'PAYMENT_CONFIG_INVALID',503);
  demand(decimal(r.amount)&&BigInt(r.amount)>0n&&Number.isSafeInteger(r.maxTimeoutSeconds)&&r.maxTimeoutSeconds>0&&r.maxTimeoutSeconds<=300,'PAYMENT_CONFIG_INVALID',503);
  demand(r.extra.assetTransferMethod==='eip3009'&&r.extra.paymentFlow==='authorization'&&typeof r.extra.name==='string'&&r.extra.name.length>0&&typeof r.extra.version==='string'&&r.extra.version.length>0,'PAYMENT_SCHEME_UNSUPPORTED',503);
  return r;
}
export function validatePayment(p,quote,at,{allowExpired=false}={}) {
  exact(p,['x402Version','accepted','payload',...['resource','extensions'].filter(k=>Object.hasOwn(p,k))]);exact(p.payload,['signature','authorization']);
  demand(p.x402Version===2,'X402_VERSION_UNSUPPORTED');
  demand(canonical(p.accepted)===canonical(quote.payload.payment_requirements),'PAYMENT_TERMS_MISMATCH');
  if(p.resource!==undefined)demand(canonical(p.resource)===canonical(quote.payload.resource),'PAYMENT_RESOURCE_MISMATCH');
  const a=p.payload.authorization;exact(a,['from','to','value','validAfter','validBefore','nonce']);
  demand(EVM_ADDRESS.test(a.from)&&EVM_ADDRESS.test(a.to),'PAYMENT_ADDRESS_INVALID');
  demand(decimal(a.value)&&decimal(a.validAfter)&&decimal(a.validBefore),'PAYMENT_INTEGER_INVALID');
  demand(HEX32.test(a.nonce),'PAYMENT_NONCE_INVALID');
  demand(/^0x[0-9a-fA-F]{128}(?:00|01|1[bBcC])$/.test(p.payload.signature),'PAYMENT_SIGNATURE_FORMAT');
  demand(a.to.toLowerCase()===p.accepted.payTo.toLowerCase()&&a.value===p.accepted.amount,'PAYMENT_VALUE_OR_RECIPIENT_MISMATCH');
  demand(BigInt(a.validAfter)<BigInt(a.validBefore)&&BigInt(a.validAfter)<BigInt(at),'PAYMENT_NOT_YET_VALID');
  demand(BigInt(a.validBefore)-BigInt(at)<=BigInt(p.accepted.maxTimeoutSeconds)+30n,'PAYMENT_WINDOW_EXCEEDS_TERMS');
  if(!allowExpired)demand(BigInt(at)<BigInt(a.validBefore)&&at<quote.payload.expires_at,'PAYMENT_EXPIRED');
  return hash({domain:'WHP-EIP3009-PAYMENT-IDENTITY-v1',network:p.accepted.network,asset:p.accepted.asset.toLowerCase(),authorizer:a.from.toLowerCase(),nonce:a.nonce.toLowerCase()});
}
export function calldataMatches(input,a,signature) {
  if(typeof input!=='string'||input.length!==10+9*64||input.slice(0,10).toLowerCase()!==TRANSFER_SELECTOR)return false;
  const words=input.slice(10).toLowerCase().match(/.{64}/g);
  const addr=x=>'0'.repeat(24)+x.slice(2).toLowerCase();
  const sig=signature.slice(2).toLowerCase(),v=parseInt(sig.slice(128),16);const expectedV=v<27?v+27:v;
  return words[0]===addr(a.from)&&words[1]===addr(a.to)&&BigInt('0x'+words[2])===BigInt(a.value)&&BigInt('0x'+words[3])===BigInt(a.validAfter)&&BigInt('0x'+words[4])===BigInt(a.validBefore)&&words[5]===a.nonce.slice(2).toLowerCase()&&BigInt('0x'+words[6])===BigInt(expectedV)&&words[7]===sig.slice(0,64)&&words[8]===sig.slice(64,128);
}
export class EvmRail {
  constructor(config,{fetchImpl=fetch}={}) {
    this.config=config;this.fetch=fetchImpl;this.verifyCalls=0;this.settleCalls=0;
    demand(/^https:\/\//.test(config.facilitator_url)&&/^https:\/\//.test(config.rpc_url),'HTTPS_PAYMENT_ENDPOINTS_REQUIRED',503);
  }
  async request(url,body){const r=await this.fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000),redirect:'error'});demand(r.ok,'PAYMENT_PROVIDER_UNAVAILABLE',503);const text=await r.text();demand(text.length<=2000000,'PAYMENT_PROVIDER_RESPONSE_TOO_LARGE',503);return JSON.parse(text);}
  async rpc(method,params){const r=await this.request(this.config.rpc_url,{jsonrpc:'2.0',id:1,method,params});demand(!r.error,'CHAIN_READ_UNAVAILABLE',503);return r.result;}
  async startBlock(){const chain=await this.rpc('eth_chainId',[]);demand('eip155:'+BigInt(chain).toString()===this.config.network,'RPC_CHAIN_MISMATCH',503);return Number(BigInt(await this.rpc('eth_blockNumber',[])));}
  facilitatorPayload(payment){return this.config.discovery_extensions?{...payment,extensions:this.config.discovery_extensions}:payment;}
  async facilitatorRequest(phase,payment,requirements){
    const url=this.config.facilitator_url.replace(/\/$/,'')+'/'+phase;
    const payload=this.facilitatorPayload(payment);
    const r=await this.fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({x402Version:2,paymentPayload:payload,paymentRequirements:requirements}),signal:AbortSignal.timeout(15000),redirect:'error'});
    demand(r.ok,'PAYMENT_PROVIDER_UNAVAILABLE',503);const text=await r.text();demand(text.length<=2000000,'PAYMENT_PROVIDER_RESPONSE_TOO_LARGE',503);
    const out=JSON.parse(text),raw=r.headers.get('extension-responses');
    // Provider metadata is recorded, not trusted as proof of standing or settlement.
    out.whp_discovery_evidence={phase,facilitator_origin:new URL(url).origin,metadata_sha256:hash(payload.extensions??{}),extension_responses_base64:raw&&raw.length<=32768?raw:null,observed_at:Math.floor(Date.now()/1000),registration_claim:false};
    return out;
  }
  async verify(payment,requirements){this.verifyCalls++;const r=await this.facilitatorRequest('verify',payment,requirements);
    demand(r.isValid===true&&typeof r.payer==='string'&&r.payer.toLowerCase()===payment.payload.authorization.from.toLowerCase(),'PAYMENT_SIGNATURE_OR_STATE_INVALID',402);return r;}
  async settle(payment,requirements){this.settleCalls++;return this.facilitatorRequest('settle',payment,requirements);}
  async evidence(payment,transaction,at) {
    if(!HEX32.test(transaction??''))return null;
    const chain=await this.rpc('eth_chainId',[]);demand('eip155:'+BigInt(chain).toString()===payment.accepted.network,'RPC_CHAIN_MISMATCH',503);
    const receipt=await this.rpc('eth_getTransactionReceipt',[transaction]);if(!receipt||receipt.status!=='0x1')return null;
    const finalized=await this.rpc('eth_getBlockByNumber',['finalized',false]);if(!finalized||BigInt(receipt.blockNumber)>BigInt(finalized.number))return null;
    const block=await this.rpc('eth_getBlockByNumber',[receipt.blockNumber,false]);
    if(!block||block.hash.toLowerCase()!==receipt.blockHash.toLowerCase())return null;
    const tx=await this.rpc('eth_getTransactionByHash',[transaction]);const a=payment.payload.authorization, token=payment.accepted.asset.toLowerCase();
    if(!tx||tx.hash.toLowerCase()!==transaction.toLowerCase()||tx.to?.toLowerCase()!==token||tx.blockHash?.toLowerCase()!==receipt.blockHash.toLowerCase()||!calldataMatches(tx.input,a,payment.payload.signature))return null;
    const relevant=receipt.logs.filter(l=>l.address.toLowerCase()===token&&!l.removed&&l.transactionHash.toLowerCase()===transaction.toLowerCase()&&l.blockHash.toLowerCase()===receipt.blockHash.toLowerCase());
    const auth=relevant.filter(l=>l.topics.length===3&&l.topics[0].toLowerCase()===AUTH_TOPIC&&l.topics[1].toLowerCase()===wordAddress(a.from)&&l.topics[2].toLowerCase()===a.nonce.toLowerCase());
    const transfers=relevant.filter(l=>l.topics.length===3&&l.topics[0].toLowerCase()===TRANSFER_TOPIC&&l.topics[1].toLowerCase()===wordAddress(a.from)&&l.topics[2].toLowerCase()===wordAddress(a.to)&&/^0x[0-9a-fA-F]{64}$/.test(l.data)&&BigInt(l.data)===BigInt(a.value));
    if(auth.length!==1||transfers.length!==1)return null;
    return {version:'WHP-EIP3009-SETTLEMENT-EVIDENCE-v1',environment:'LIVE',network:payment.accepted.network,asset:payment.accepted.asset,
      payer:a.from,pay_to:a.to,amount:a.value,nonce:a.nonce,transaction:transaction.toLowerCase(),
      block_number:Number(BigInt(receipt.blockNumber)),block_hash:receipt.blockHash,finality:'finalized',
      finalized_head:{number:finalized.number,hash:finalized.hash},observed_at:at,
      authorization_log:auth[0],transfer_log:transfers[0],transaction_input:tx.input,
      verification_boundary:'Read from configured chain RPC. Independently recheck against a trusted RPC; this is not a self-contained consensus inclusion proof.'};
  }
  async reconcile(row,at) {
    if(row.transaction_hint){const e=await this.evidence(row.payment_payload,row.transaction_hint,at);if(e)return e;}
    const head=await this.rpc('eth_getBlockByNumber',['finalized',false]);if(!head)return null;
    const p=row.payment_payload,a=p.payload.authorization;
    let from=row.scan_from??row.observed_block;const to=Number(BigInt(head.number));
    // Persist the returned cursor. Bound each HTTP run, rather than losing old history.
    const end=Math.min(to,from+1999);
    if(from>end)return null;
    const logs=await this.rpc('eth_getLogs',[{address:p.accepted.asset,fromBlock:'0x'+from.toString(16),toBlock:'0x'+end.toString(16),topics:[AUTH_TOPIC,wordAddress(a.from),a.nonce]}]);
    demand(Array.isArray(logs),'CHAIN_LOGS_INVALID',503);
    for(const l of logs){const e=await this.evidence(p,l.transactionHash,at);if(e)return e;}
    return {scan_only:true,next_scan_from:end+1};
  }
}
