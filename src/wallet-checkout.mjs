// Transport preparation only. Uses StandingBuyer's existing EIP-712 definition and
// the frozen quote-bound nonce. This module never signs or authorizes buyer spending.
import {demand} from './canonical.mjs';
import {authorizationNonce,EVM_ADDRESS} from './payment.mjs';
import {typedAuthorization} from './buyer.mjs';

export const PAYER_HEADER='payment-payer';
export const WALLET_SIGNATURE_HEADER='payment-wallet-signature';

export function quotedAuthorization(quote,payer){
  demand(typeof payer==='string'&&EVM_ADDRESS.test(payer),'PAYMENT_PAYER_INVALID');
  const q=quote.payload,t=q.payment_requirements;
  // Derived from the DURABLE original quote, never the current retry clock.
  return {from:payer.toLowerCase(),to:t.payTo,value:t.amount,validAfter:String(q.issued_at-1),
    validBefore:String(Math.min(q.issued_at+t.maxTimeoutSeconds,q.expires_at)),nonce:authorizationNonce(quote)};
}

export function walletPayment(quote,payer,signature){
  return {x402Version:2,resource:quote.payload.resource,accepted:quote.payload.payment_requirements,
    payload:{signature,authorization:quotedAuthorization(quote,payer)}};
}

export function walletCheckout(service,row,payer,decision){
  const authorization=quotedAuthorization(row.quote,payer);
  demand(service.clock()<Number(authorization.validBefore),'WALLET_AUTHORIZATION_EXPIRED',409);
  return {version:'WHP-WALLET-CHECKOUT-v1',purchase_id:row.id,request_hash:row.request_hash,
    buyer_installation_required:false,buyer_authentication_signature_required:false,
    eligibility:{observed_at:decision.evaluated_at,outcome:decision.outcome,
      can_produce_mark:decision.outcome==='ESTABLISHED',failed_checks:decision.checks.filter(c=>!c.passed).map(({rule,object})=>({rule,object})),
      meaning:'Unpaid observation of this exact submitted object, not a Mark or new authority. Payment purchases an evaluation, including a negative assessment; issuance still requires the original checks and finalized settlement.'},
    wallet_request:{method:'eth_signTypedData_v4',params:[authorization.from,JSON.stringify(typedAuthorization(row.quote.payload.payment_requirements,authorization))]},
    submit:{method:'POST',url:row.quote.payload.resource.url,body:'RESEND_ORIGINAL_SUBMISSION_UNCHANGED',
      payer_header:PAYER_HEADER,payer:authorization.from,signature_header:WALLET_SIGNATURE_HEADER,
      mcp:{tool:'whp_standing_evaluation',submission_argument:'submission_raw',payer_argument:'payer',signature_argument:'wallet_signature'}},
    recovery:{result_url:service.origin+'/v1/purchases/'+row.id+'/result',recover_url:service.origin+'/v1/purchases/'+row.id+'/recover',
      mcp_result_tool:'whp_standing_result',mcp_recover_tool:'whp_standing_recover',additional_charge:false,
      instruction:'Persist the original submission, purchase ID and wallet signature before sending. On interruption retrieve/recover this purchase; if still QUOTED, resend the identical signature. Never authorize a second payment.'},
    owner_policy:'The existing buyer wallet/runtime must enforce owner-approved recipient, token, network, purpose, per-purchase and aggregate spending limits before signing. Server instructions grant no wallet authority.',
    compatibility:'Existing EIP-712/EIP-3009 EOA wallet signing, 65-byte signatures. This is a transport adapter for WHP exact-quote binding, optional; standard random-nonce x402 is also supported.'};
}
