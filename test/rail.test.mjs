import test from 'node:test';import assert from 'node:assert/strict';
import {EvmRail,AUTH_TOPIC,TRANSFER_TOPIC,TRANSFER_SELECTOR,wordAddress} from '../src/payment.mjs';
import {setup,paymentFor,NOW} from './fixtures.mjs';import {clone} from '../src/canonical.mjs';
function rpcData(payment){
  const a=payment.payload.authorization,txid='0x'+'ab'.repeat(32),bh='0x'+'cd'.repeat(32),w=n=>BigInt(n).toString(16).padStart(64,'0');
  const input=TRANSFER_SELECTOR+wordAddress(a.from).slice(2)+wordAddress(a.to).slice(2)+w(a.value)+w(a.validAfter)+w(a.validBefore)+a.nonce.slice(2)+w(27)+'11'.repeat(64);
  const base={address:payment.accepted.asset,removed:false,transactionHash:txid,blockHash:bh,blockNumber:'0x65'};
  return {txid,chain:'0x2105',finalized:{number:'0x66',hash:'0x'+'ef'.repeat(32)},block:{number:'0x65',hash:bh},
    receipt:{status:'0x1',transactionHash:txid,blockHash:bh,blockNumber:'0x65',logs:[{...base,logIndex:'0x0',topics:[AUTH_TOPIC,wordAddress(a.from),a.nonce],data:'0x'},{...base,logIndex:'0x1',topics:[TRANSFER_TOPIC,wordAddress(a.from),wordAddress(a.to)],data:'0x'+w(a.value)}]},
    tx:{hash:txid,to:payment.accepted.asset,blockHash:bh,input}};
}
function railFor(data){return new EvmRail({network:'eip155:8453',facilitator_url:'https://facilitator.invalid',rpc_url:'https://rpc.invalid'},{fetchImpl:async(url,options)=>{
  const b=JSON.parse(options.body);let result;
  if(url.endsWith('/verify'))return Response.json({isValid:true,payer:data.payer});
  if(url.endsWith('/settle'))return Response.json({success:true,network:'eip155:8453',transaction:data.txid});
  switch(b.method){case'eth_chainId':result=data.chain;break;case'eth_blockNumber':result='0x64';break;case'eth_getTransactionReceipt':result=data.receipt;break;case'eth_getBlockByNumber':result=b.params[0]==='finalized'?data.finalized:data.block;break;case'eth_getTransactionByHash':result=data.tx;break;case'eth_getLogs':result=data.receipt?.logs.slice(0,1)??[];break;default:throw Error('Unexpected RPC '+b.method);}
  return Response.json({jsonrpc:'2.0',id:1,result});
}});}

test('EVM adapter matches finalized canonical receipt, exact calldata, authorization nonce and value transfer under mocked RPC',async()=>{const x=await setup();try{const q=await x.start(),p=paymentFor(q.quote),d=rpcData(p);const rail=railFor(d),proof=await rail.evidence(p,d.txid,NOW);assert.equal(proof.finality,'finalized');assert.equal(proof.amount,p.accepted.amount);assert.equal(proof.nonce,p.payload.authorization.nonce);assert.equal(proof.environment,'LIVE');}finally{await x.store.close();}});
for(const [name,mutate] of [
  ['unmined',d=>d.receipt=null],['failed transaction',d=>d.receipt.status='0x0'],['not finalized',d=>d.finalized.number='0x64'],
  ['reorged block',d=>d.block.hash='0x'+'00'.repeat(32)],['wrong token',d=>d.tx.to='0x'+'99'.repeat(20)],
  ['wrong nonce event',d=>d.receipt.logs[0].topics[2]='0x'+'00'.repeat(32)],['missing authorization event',d=>d.receipt.logs.shift()],
  ['wrong transfer amount',d=>d.receipt.logs[1].data='0x'+'00'.repeat(31)+'01'],['wrong recipient',d=>d.receipt.logs[1].topics[2]=wordAddress('0x'+'99'.repeat(20))],
  ['removed event',d=>d.receipt.logs[0].removed=true],['wrong calldata',d=>d.tx.input=TRANSFER_SELECTOR+'00'.repeat(288)],
  ['different transaction identity',d=>d.tx.hash='0x'+'00'.repeat(32)],['duplicate transfer event',d=>d.receipt.logs.push(clone(d.receipt.logs[1]))]
])test('EVM adapter refuses '+name+' evidence',async()=>{const x=await setup();try{const q=await x.start(),p=paymentFor(q.quote),d=rpcData(p);mutate(d);assert.equal(await railFor(d).evidence(p,d.txid,NOW),null);}finally{await x.store.close();}});
test('EVM adapter rejects wrong RPC chain even with matching-looking receipt',async()=>{const x=await setup();try{const q=await x.start(),p=paymentFor(q.quote),d=rpcData(p);d.chain='0x1';await assert.rejects(()=>railFor(d).evidence(p,d.txid,NOW),/RPC_CHAIN_MISMATCH/);}finally{await x.store.close();}});
test('settlement response success is not finality; recovery discovers exact authorization event',async()=>{const x=await setup();try{const q=await x.start(),p=paymentFor(q.quote),d=rpcData(p),rail=railFor(d);const record={payment_payload:p,observed_block:100,scan_from:100};const proof=await rail.reconcile(record,NOW);assert.equal(proof.transaction,d.txid);d.receipt=null;assert.equal((await rail.settle(p,p.accepted)).success,true);const absent=await rail.reconcile(record,NOW);assert.equal(absent.scan_only,true);}finally{await x.store.close();}});
