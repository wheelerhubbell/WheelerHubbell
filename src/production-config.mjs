// Public production configuration is source-owned and provider-neutral.
// Hosting may supply infrastructure/secrets, but may not redefine WHP trust or payment semantics.
export const DEFAULT_FACILITATOR_URL='https://facilitator.payai.network';
export const DEFAULT_RPC_URL='https://base-rpc.publicnode.com';
export const PRODUCTION_PAYMENT_REQUIREMENTS=Object.freeze({
  scheme:'exact',
  network:'eip155:8453',
  amount:'1000000',
  asset:'0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
  payTo:'0x1050eddd8282623b0c263ed6bdbd42370bbc28d3',
  maxTimeoutSeconds:300,
  extra:Object.freeze({assetTransferMethod:'eip3009',paymentFlow:'authorization',name:'USD Coin',version:'2'})
});

const cleanOrigin=v=>typeof v==='string'&&v.length?(/^https?:\/\//.test(v)?v:'https://'+v).replace(/\/$/,''):undefined;
export function runtimeDefaults(env={}){
  return {
    origin:cleanOrigin(env.WHP_ORIGIN??env.URL??env.DEPLOY_PRIME_URL??env.VERCEL_PROJECT_PRODUCTION_URL??env.VERCEL_URL),
    facilitatorUrl:env.WHP_FACILITATOR_URL??DEFAULT_FACILITATOR_URL,
    rpcUrl:env.WHP_RPC_URL??DEFAULT_RPC_URL
  };
}
