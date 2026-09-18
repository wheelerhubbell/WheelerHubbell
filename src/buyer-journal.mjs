import {DatabaseSync} from 'node:sqlite';
import {canonical,hash,demand} from './canonical.mjs';

// The reservation is committed BEFORE the wallet signer is invoked. Uncertain purchases
// retain their budget reservation; a retry never silently receives a new allowance.
export class BuyerJournal {
  constructor(filename){
    this.db=new DatabaseSync(filename);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS buyer_purchases(
        id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
        reserved_amount TEXT NOT NULL DEFAULT '0', record TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS buyer_trust_heads(root_pin TEXT PRIMARY KEY, sequence BIGINT NOT NULL, snapshot_hash TEXT NOT NULL);`);
  }
  transaction(fn){this.db.exec('BEGIN IMMEDIATE');try{const value=fn();this.db.exec('COMMIT');return value;}catch(e){this.db.exec('ROLLBACK');throw e;}}
  get(id){const r=this.db.prepare('SELECT record FROM buyer_purchases WHERE id=?').get(id);return r?JSON.parse(r.record):null;}
  begin(id,submission,policy){return this.transaction(()=>{
    const old=this.get(id),ph=hash(policy),sh=hash(submission);
    if(old){demand(old.request_hash===sh&&old.policy_hash===ph,'BUYER_IDEMPOTENCY_CONFLICT',409);return old;}
    const row={id,submission,policy_hash:ph,request_hash:sh,state:'STARTED'};
    this.db.prepare('INSERT INTO buyer_purchases(id,request_hash,policy_hash,record) VALUES(?,?,?,?)').run(id,sh,ph,canonical(row));return row;
  });}
  reserve(id,quote,policy){return this.transaction(()=>{
    const row=this.get(id);demand(row,'BUYER_PURCHASE_UNKNOWN');
    if(row.quote){demand(hash(row.quote)===hash(quote),'BUYER_QUOTE_CONFLICT');return row;}
    const amount=BigInt(quote.payload.payment_requirements.amount);
    demand(amount>0n&&amount<=BigInt(policy.max_per_purchase),'BUYER_PER_PURCHASE_LIMIT');
    let reserved=0n;for(const r of this.db.prepare('SELECT reserved_amount FROM buyer_purchases WHERE policy_hash=?').all(row.policy_hash))reserved+=BigInt(r.reserved_amount);
    demand(reserved+amount<=BigInt(policy.max_total),'BUYER_TOTAL_SPENDING_LIMIT');
    const next={...row,state:'RESERVED',quote};
    this.db.prepare('UPDATE buyer_purchases SET reserved_amount=?,record=? WHERE id=?').run(String(amount),canonical(next),id);return next;
  });}
  authorize(id,payment){return this.transaction(()=>{const row=this.get(id);demand(row?.quote,'BUYER_QUOTE_REQUIRED');if(row.payment)return row;
    const next={...row,state:'AUTHORIZED',payment};this.db.prepare('UPDATE buyer_purchases SET record=? WHERE id=?').run(canonical(next),id);return next;
  });}
  accept(id,bytes,registry,verification){return this.transaction(()=>{const row=this.get(id);demand(row?.payment,'BUYER_AUTHORIZATION_REQUIRED');
    if(row.result_bytes)demand(row.result_bytes===bytes,'BUYER_RESULT_CHANGED');
    const next={...row,state:'VERIFIED',result_bytes:bytes,registry,verification};this.db.prepare('UPDATE buyer_purchases SET record=? WHERE id=?').run(canonical(next),id);return next;
  });}
  rememberTrust(rootPin,signedStatus){return this.transaction(()=>{
    const sequence=signedStatus.payload.sequence,digest=hash(signedStatus);
    demand(Number.isSafeInteger(sequence)&&sequence>=0,'BUYER_TRUST_SEQUENCE_INVALID');
    const old=this.db.prepare('SELECT sequence,snapshot_hash FROM buyer_trust_heads WHERE root_pin=?').get(rootPin);
    if(old)demand(sequence>old.sequence||(sequence===old.sequence&&digest===old.snapshot_hash),'BUYER_TRUST_ROLLBACK');
    this.db.prepare('INSERT INTO buyer_trust_heads(root_pin,sequence,snapshot_hash) VALUES(?,?,?) ON CONFLICT(root_pin) DO UPDATE SET sequence=excluded.sequence,snapshot_hash=excluded.snapshot_hash').run(rootPin,sequence,digest);
  });}
  close(){this.db.close();}
}
