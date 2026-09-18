import {canonical,hash,parseStrict,openSeal,demand,encode,randomHex} from './canonical.mjs';
import {validateTrust,issuerAuthority} from './authority.mjs';
import {validateSubmission} from './validation.mjs';
import {authorizationNonce,validatePayment,EVM_ADDRESS} from './payment.mjs';
import {PROFILE_HASH} from './profile.mjs';

// Public purchase capability; no buyer authentication key is required.
const purchaseId=(s,pin)=>hash({domain:'WHP-STANDING-PURCHASE-v1.1',root_pin:pin,client_reference:s.client_reference});

// Adapter for the buyer owner's EXISTING EIP-1193 spending-authorized wallet provider.
// No wallet is created, funded, or granted authority by this module.
export class Eip1193Signer {
  constructor(provider){demand(typeof provider?.request==='function','EIP1193_PROVIDER_REQUIRED');this.provider=provider;}
  async signTypedData(payer,data){return this.provider.request({method:'eth_signTypedData_v4',params:[payer,JSON.stringify(data)]});}
}
export function typedAuthorization(terms,authorization){return {
  types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],
    TransferWithAuthorization:[{name:'from',type:'address'},{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'validAfter',type:'uint256'},{name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}]},
  primaryType:'TransferWithAuthorization',domain:{name:terms.extra.name,version:terms.extra.version,chainId:terms.network.slice(7),verifyingContract:terms.asset},message:authorization};}
export class StandingBuyer {
  constructor({policy,paymentSigner,journal,verifyResult,fetchImpl=fetch,clock=()=>Math.floor(Date.now()/1000)}){
    demand(/^https:\/\//.test(policy.origin)||(policy.environment==='TEST'&&/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(policy.origin)),'BUYER_ORIGIN_INVALID');
    demand(['TEST','LIVE'].includes(policy.environment)&&/^[0-9a-f]{64}$/.test(policy.root_pin)&&policy.profile_hash===PROFILE_HASH,'BUYER_TRUST_POLICY_INVALID');
    demand(/^eip155:[1-9][0-9]*$/.test(policy.network)&&[policy.asset,policy.pay_to,policy.payer].every(a=>typeof a==='string'&&EVM_ADDRESS.test(a)),'BUYER_ASSET_POLICY_INVALID');
    demand([policy.max_per_purchase,policy.max_total].every(a=>typeof a==='string'&&/^[1-9][0-9]*$/.test(a)),'BUYER_BUDGET_REQUIRED');
    demand(typeof verifyResult==='function'&&typeof paymentSigner?.signTypedData==='function','BUYER_SIGNER_AND_INDEPENDENT_VERIFIER_REQUIRED');
    Object.assign(this,{policy,paymentSigner,journal,verifyResult,fetch:fetchImpl,clock});
  }
  async request(method,path,body='',payment=null){const headers={'content-type':'application/json'};if(payment)headers['payment-signature']=encode(payment);
    return this.fetch(this.policy.origin+path,{method,headers,...(method!=='GET'?{body}:{}),redirect:'error',signal:AbortSignal.timeout(30000)});}
  async discover(){
    const response=await this.request('GET','/.well-known/whp-standing.json');demand(response.ok,'BUYER_DISCOVERY_UNAVAILABLE');
    const d=parseStrict(await response.text(),1048576),trust=validateTrust(d.trust_bundle,this.policy.root_pin,this.clock());
    this.journal.rememberTrust(this.policy.root_pin,d.trust_bundle.status_snapshot);
    demand(hash(d.profile)===this.policy.profile_hash&&trust.profile.environment===this.policy.environment,'BUYER_PROFILE_OR_ENVIRONMENT_MISMATCH');
    return {d,trust};
  }
  async quoteCheck(terms,s,discovery){
    demand(terms.x402Version===2&&terms.extensions?.['whp-standing']?.info?.quote,'BUYER_X402_BINDING_EXTENSION_REQUIRED');
    const {d,trust}=discovery??await this.discover();
    const quote=terms.extensions['whp-standing'].info.quote,cert=issuerAuthority(quote.protected.key_id,s.bounds.scope,s.bounds.jurisdiction,trust),q=openSeal(quote,'WHP-STANDING-QUOTE-v1.1',cert.public_key);
    demand(q.environment===this.policy.environment&&q.issuer===trust.profile.issuer&&q.profile_hash===this.policy.profile_hash,'BUYER_QUOTE_ISSUER_MISMATCH');
    demand(q.purchase_id===purchaseId(s,this.policy.root_pin)&&q.request_hash===hash(s)&&q.client_reference===s.client_reference,'BUYER_QUOTE_SUBMISSION_MISMATCH');
    demand(q.issued_at<=this.clock()+30&&this.clock()<q.expires_at&&q.expires_at<=cert.valid_until&&q.expires_at<=trust.profile.valid_until,'BUYER_QUOTE_EXPIRED');
    const t=q.payment_requirements,p=this.policy;
    demand(q.resource.url===p.origin+'/v1/evaluations'&&canonical(terms.resource)===canonical(q.resource)&&canonical(terms.accepts)===canonical([t]),'BUYER_RESOURCE_MISMATCH');
    demand(t.scheme==='exact'&&t.network===p.network&&t.asset.toLowerCase()===p.asset.toLowerCase()&&t.payTo.toLowerCase()===p.pay_to.toLowerCase(),'BUYER_PAYMENT_DESTINATION_NOT_AUTHORIZED');
    demand(t.extra.assetTransferMethod==='eip3009'&&t.extra.paymentFlow==='authorization'&&t.extra.name===p.asset_name&&t.extra.version===p.asset_version,'BUYER_EIP712_DOMAIN_NOT_AUTHORIZED');
    demand(Number.isSafeInteger(t.maxTimeoutSeconds)&&t.maxTimeoutSeconds>0&&t.maxTimeoutSeconds<=300,'BUYER_TIMEOUT_NOT_AUTHORIZED');
    demand(typeof t.amount==='string'&&/^[1-9][0-9]*$/.test(t.amount)&&BigInt(t.amount)<=BigInt(p.max_per_purchase),'BUYER_PER_PURCHASE_LIMIT');return quote;
  }
  async accept(response,row){
    demand(response.status===200,'BUYER_RESULT_NOT_READY');const bytes=await response.text(),p=parseStrict(bytes,1048576).payload;
    demand(p.purchase_id===row.id&&p.submission_hash===row.request_hash&&hash(p.commerce.quote)===hash(row.quote),'BUYER_RESULT_SUBSTITUTION');
    const registry=await this.request('GET','/v1/registry/'+row.id);demand(registry.ok,'BUYER_REGISTRY_UNAVAILABLE');const registryBytes=await registry.text();
    const verification=await this.verifyResult(bytes,registryBytes,this.clock());
    demand(verification.verified===true&&verification.environment===this.policy.environment,'BUYER_INDEPENDENT_VERIFICATION_FAILED');
    if(this.policy.environment==='LIVE')demand(verification.payment_chain_finality==='FINALIZED_RECHECKED_AGAINST_SUPPLIED_RPC','BUYER_FINALITY_NOT_VERIFIED');
    this.journal.rememberTrust(this.policy.root_pin,parseStrict(registryBytes,1048576).payload.trust_bundle.status_snapshot);
    this.journal.accept(row.id,bytes,registryBytes,verification);
    return {purchase_id:row.id,state:'VERIFIED',result_bytes:bytes,verification};
  }
  async retrieve(submission){const id=purchaseId(submission,this.policy.root_pin),row=this.journal.get(id);demand(row?.payment,'BUYER_PURCHASE_UNKNOWN');
    const response=await this.request('GET','/v1/purchases/'+id+'/result');if(response.status!==200)return {purchase_id:id,state:'PENDING',http_status:response.status};return this.accept(response,row);}
  async purchase(submission){
    const s=validateSubmission(submission);
    const id=purchaseId(s,this.policy.root_pin);let row=this.journal.begin(id,s,this.policy),response;
    if(row.payment){
      // Lost-response / process-restart recovery never contacts the wallet again.
      response=await this.request('GET','/v1/purchases/'+id+'/result');
      if(response.status===200)return this.accept(response,row);
      if(response.status===202){const status=parseStrict(await response.text());
        if(status.state!=='QUOTED')response=await this.request('POST','/v1/purchases/'+id+'/recover');
        else response=await this.request('POST','/v1/evaluations',canonical(s),row.payment);
      }else if(response.status===404)response=await this.request('POST','/v1/evaluations',canonical(s),row.payment);
      else if(response.status>=500||[408,429].includes(response.status))return {purchase_id:id,state:'PENDING',http_status:response.status,additional_charge:false};
      else demand(false,'BUYER_RECOVERY_REFUSED');
    } else {
      if(!row.quote){const discovered=await this.discover();const unpaid=await this.request('POST','/v1/evaluations',canonical(s));demand(unpaid.status===402,'BUYER_QUOTE_REQUIRED');
        const quote=await this.quoteCheck(parseStrict(await unpaid.text(),1048576),s,discovered);row=this.journal.reserve(id,quote,this.policy);}
      const at=this.clock(),q=row.quote,t=q.payload.payment_requirements;
      demand(at<q.payload.expires_at,'BUYER_STORED_QUOTE_EXPIRED');
      const authorization={from:this.policy.payer,to:t.payTo,value:t.amount,validAfter:String(at-1),validBefore:String(Math.min(at+t.maxTimeoutSeconds,q.payload.expires_at)),nonce:'0x'+randomHex(32)};
      const signature=await this.paymentSigner.signTypedData(this.policy.payer,typedAuthorization(t,authorization));
      const payment={x402Version:2,resource:q.payload.resource,accepted:t,payload:{signature,authorization}};
      validatePayment(payment,q,at);row=this.journal.authorize(id,payment);
      response=await this.request('POST','/v1/evaluations',canonical(s),row.payment);
    }
    if(response.status===200)return this.accept(response,row);
    if(response.status>=500||[408,429].includes(response.status))return {purchase_id:id,state:'PENDING',http_status:response.status,additional_charge:false};
    demand(response.status===202,'BUYER_EVALUATION_REFUSED');return {purchase_id:id,state:'PENDING',additional_charge:false};
  }
}
