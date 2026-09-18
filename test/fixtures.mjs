import {CONTRACT_HASH,VERIFIER_HASH} from '../src/protocol.mjs';
import {generateKeyPairSync} from 'node:crypto';
import {sqliteStore} from '../src/store.mjs';
import {publicDer,keyId,seal,hash,canonical,clone,randomHex,encode} from '../src/canonical.mjs';
import {profile,PROFILE_HASH,PROFILE_ID,PROFILE_VERSION} from '../src/profile.mjs';
import {StandingService,clientProof} from '../src/service.mjs';
import {authorizationNonce,validatePayment} from '../src/payment.mjs';
export const NOW=Math.floor(Date.parse('2026-09-15T08:48:10Z')/1000);
const keys=()=>generateKeyPairSync('ed25519');
export function fixture({at=NOW}={}){
  const root=keys(),issuer=keys(),source=keys(),transition=keys(),buyer=keys();
  const scope='submitted-example-only',jurisdiction='test-fixture-not-external-authority';
  const bounds={scope,jurisdiction,valid_from:at-100,valid_until:at+3600};
  const rootPub=publicDer(root.privateKey),rootPin=keyId(rootPub);
  const cert=(k,subject,roles)=>seal('WHP-AUTHORITY-CERTIFICATE-v1',{public_key:publicDer(k.privateKey),subject,roles,scopes:[scope],jurisdictions:[jurisdiction],operations:['INFORM','RECOMMEND','EXECUTE'],profile_hash:PROFILE_HASH,valid_from:at-1000,valid_until:at+604800},root.privateKey);
  const trustBundle={root_public_key:rootPub,profile_authorization:seal('WHP-PROFILE-AUTHORIZATION-v1',{
    profile_hash:PROFILE_HASH,contract_hash:CONTRACT_HASH,verifier_sha256:VERIFIER_HASH,ratified:true,issuer:'WHP Standing test issuer — not an institutional issuance',environment:'TEST',valid_from:at-1000,valid_until:at+604800},root.privateKey),
    certificates:[cert(issuer,'test-issuer',['ISSUER','REGISTRY','DISCOVERY']),cert(source,'test-source-attestor',['SOURCE']),cert(transition,'test-transition-authority',['TRANSITION'])],revocations:[]};
  trustBundle.status_snapshot=seal('WHP-TRUST-STATUS-v1',{sequence:0,previous_hash:null,profile_authorization_hash:hash(trustBundle.profile_authorization),certificates_hash:hash(trustBundle.certificates),revocations_hash:hash(trustBundle.revocations),valid_from:at-1000,valid_until:at+604800},root.privateKey);
  const leaf={id:'sample-observation',version:'1',content:{statement:'Three items are present in this submitted fixture.',count:3},locator:'urn:whp:test:source-1',epistemic_status:'REPORT',
    qualifiers:['Only this submitted fixture.','No external-world truth claim.'],unknowns:[{id:'external-validity',description:'No outside-world evidence is supplied.',blocks:['EXECUTE']}],operations:['INFORM','RECOMMEND'],
    ...bounds,valid_from:at-500,valid_until:at+7200,status:'ACTIVE',prior_hash:null};
  const target={...clone(leaf),id:'preserved-representation',locator:'urn:whp:test:representation-1'};
  const att=n=>seal('WHP-SOURCE-ATTESTATION-v1',n,source.privateKey);
  const edge={from:[hash(leaf)],to:hash(target),transform:'COPY',operations:['INFORM','RECOMMEND'],...bounds,valid_from:at-500,valid_until:at+7200,
    warrant:{statement:'Exact COPY of this source for INFORM or RECOMMEND only; all qualifiers and unknowns retained.',evidence_hashes:[hash(leaf)]}};
  const submission={version:'WHP-STANDING-SUBMISSION-v1.1',client_reference:randomHex(32),authority:[],profile:{id:PROFILE_ID,version:PROFILE_VERSION,sha256:PROFILE_HASH},
    object:{id:target.id,version:target.version,root:hash(target)},bounds,requested_operation:'INFORM',nodes:[att(leaf),att(target)],transitions:[seal('WHP-TRANSITION-WARRANT-v1',edge,transition.privateKey)]};
  const requirements={scheme:'exact',network:'eip155:8453',amount:'1000000',asset:'0x'+'11'.repeat(20),payTo:'0x'+'22'.repeat(20),maxTimeoutSeconds:300,
    extra:{assetTransferMethod:'eip3009',paymentFlow:'authorization',name:'USDC',version:'2'}};
  return {root,issuer,source,transition,buyer,rootPin,trustBundle,submission,requirements,scope,jurisdiction};
}
export class FakeRail {
  constructor(){this.environment='TEST';this.verifyCalls=0;this.settleCalls=0;this.transfers=0;this.paid=new Map();this.reveal=true;this.failVerify=false;this.mode='success';}
  async startBlock(){return 100;}
  async verify(){this.verifyCalls++;if(this.failVerify)throw new Error('Simulated verification failure');return {isValid:true};}
  async settle(p){this.settleCalls++;const key=hash(p.payload.authorization);
    if(!this.paid.has(key)){this.transfers++;this.paid.set(key,{version:'WHP-TEST-SETTLEMENT-EVIDENCE-v1',environment:'TEST',network:p.accepted.network,asset:p.accepted.asset,
      payer:p.payload.authorization.from,pay_to:p.payload.authorization.to,amount:p.payload.authorization.value,nonce:p.payload.authorization.nonce,
      transaction:'0x'+hash({simulated_payment:key}),block_number:101,block_hash:'0x'+hash('simulated-block'),finality:'SIMULATED_NOT_LIVE',observed_at:NOW,
      verification_boundary:'Local deterministic payment test double. No funds moved and no chain was contacted.'});}
    if(this.mode==='timeout-after-transfer')throw new Error('Simulated lost settlement response');
    return {success:true,network:p.accepted.network,payer:p.payload.authorization.from,transaction:this.paid.get(key).transaction};
  }
  async reconcile(row){return this.reveal?(this.paid.get(hash(row.payment_payload.payload.authorization))??null):null;}
}
export function paymentFor(quote,at=NOW){return {x402Version:2,resource:quote.payload.resource,accepted:quote.payload.payment_requirements,payload:{signature:'0x'+'11'.repeat(64)+'1b',authorization:{from:'0x'+'33'.repeat(20),to:quote.payload.payment_requirements.payTo,value:quote.payload.payment_requirements.amount,validAfter:String(at-1),validBefore:String(at+240),nonce:authorizationNonce(quote)}}};}
export async function setup({filename=':memory:',f=fixture(),rail=new FakeRail(),hooks={},clock=()=>NOW}={}) {
  const store=await sqliteStore(filename);const service=new StandingService({store,rail,privateKey:f.issuer.privateKey,trustBundle:f.trustBundle,rootPin:f.rootPin,origin:'https://standing.test.invalid',requirements:f.requirements,clock,hooks});
  async function request(method,path,body='',payment=null,key=f.buyer.privateKey){const h={'content-type':'application/json','whp-client-proof':clientProof(key,method,path,body,clock())};if(payment)h['payment-signature']=encode(payment);
    return service.handle(new Request('https://standing.test.invalid'+path,{method,headers:h,...(method!=='GET'?{body}: {})}));}
  async function start(s=f.submission){const raw=canonical(s);const r=await request('POST','/v1/evaluations',raw);const terms=await r.json();return {response:r,raw,terms,quote:terms.extensions?.['whp-standing'].info.quote};}
  async function purchase(s=f.submission){const q=await start(s);const payment=paymentFor(q.quote,clock());const r=await request('POST','/v1/evaluations',q.raw,payment);return {...q,payment,response:r,bytes:await r.text()};}
  return {f,store,rail,service,request,start,purchase};
}
export function resignTarget(f,change){const s=clone(f.submission),old=s.object.root,n=clone(s.nodes[1].payload);change(n);s.nodes[1]=seal('WHP-SOURCE-ATTESTATION-v1',n,f.source.privateKey);s.object.root=hash(n);s.object.id=n.id;s.object.version=n.version;
  const t=clone(s.transitions[0].payload);t.to=hash(n);s.transitions[0]=seal('WHP-TRANSITION-WARRANT-v1',t,f.transition.privateKey);return s;}

export function refreshTrustStatus(f){const previous=f.trustBundle.status_snapshot;f.trustBundle.status_snapshot=seal('WHP-TRUST-STATUS-v1',{...previous.payload,sequence:previous.payload.sequence+1,previous_hash:hash(previous),profile_authorization_hash:hash(f.trustBundle.profile_authorization),certificates_hash:hash(f.trustBundle.certificates),revocations_hash:hash(f.trustBundle.revocations)},f.root.privateKey);}
