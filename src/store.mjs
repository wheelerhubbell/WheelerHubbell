import { createHash } from 'node:crypto';
import { hash, canonical, demand, Fault, clone } from './canonical.mjs';

const migration=`
CREATE TABLE IF NOT EXISTS purchases(
 id TEXT PRIMARY KEY, buyer_key TEXT NOT NULL, client_reference TEXT NOT NULL,
 request_hash TEXT NOT NULL, state TEXT NOT NULL,
 payment_key TEXT UNIQUE, record TEXT NOT NULL, result_bytes TEXT,
 lease_owner TEXT, lease_until BIGINT NOT NULL DEFAULT 0,
 UNIQUE(buyer_key,client_reference)
);
CREATE TABLE IF NOT EXISTS registry_events(
 purchase_id TEXT NOT NULL REFERENCES purchases(id), sequence INTEGER NOT NULL,
 event_bytes TEXT NOT NULL, event_hash TEXT NOT NULL,
 PRIMARY KEY(purchase_id,sequence)
);
CREATE TABLE IF NOT EXISTS review_requests(
 review_id TEXT PRIMARY KEY, purchase_id TEXT NOT NULL REFERENCES purchases(id), record TEXT NOT NULL
);
`;

export class Store {
  constructor(driver) {this.driver=driver;this.calls=0;}
  async initialize(){await this.driver.script(migration);}
  async get(id){this.calls++;const rows=await this.driver.query('SELECT record, result_bytes FROM purchases WHERE id=$1',[id]);
    if(!rows.length)return null;return {...JSON.parse(rows[0].record),result_bytes:rows[0].result_bytes};}
  async quote(row){this.calls++;return this.driver.transaction(async tx=>{
    await tx.query('INSERT INTO purchases(id,buyer_key,client_reference,request_hash,state,record) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
      [row.id,row.buyer_key,row.client_reference,row.request_hash,row.state,canonical(row)]);
    const [existing]=await tx.query('SELECT record FROM purchases WHERE id=$1'+tx.lock,[row.id]);
    demand(existing,'QUOTE_STORAGE_FAILED',503);const old=JSON.parse(existing.record);
    demand(old.request_hash===row.request_hash,'IDEMPOTENCY_CONFLICT',409);return old;
  });}
  async reserve(id,expectedHash,prepared){this.calls++;return this.driver.transaction(async tx=>{
    const [r]=await tx.query('SELECT record,state FROM purchases WHERE id=$1'+tx.lock,[id]);demand(r,'PURCHASE_NOT_FOUND',404);
    const old=JSON.parse(r.record);demand(old.request_hash===expectedHash,'IDEMPOTENCY_CONFLICT',409);
    if(old.state!=='QUOTED'){demand(old.payment_key===prepared.payment_key,'PURCHASE_ALREADY_BOUND',409);return old;}
    const next={...old,...prepared,state:'PREPARED'};
    try {await tx.query('UPDATE purchases SET record=$1,state=$2,payment_key=$3 WHERE id=$4',[canonical(next),next.state,next.payment_key,id]);}
    catch(e){if(e.code==='23505'||String(e.message).includes('UNIQUE'))throw new Fault('PAYMENT_REPLAY',409);throw e;}
    return next;
  });}
  async lease(id,owner,now,seconds=90){this.calls++;const r=await this.driver.query(
    'UPDATE purchases SET lease_owner=$1,lease_until=$2 WHERE id=$3 AND lease_until<=$4 AND state<>$5 RETURNING id',[owner,now+seconds,id,now,'ISSUED']);return r.length>0;}
  async update(id,owner,mutate){this.calls++;return this.driver.transaction(async tx=>{
    const [r]=await tx.query('SELECT record,lease_owner FROM purchases WHERE id=$1'+tx.lock,[id]);
    demand(r&&r.lease_owner===owner,'LEASE_LOST',409);const row=JSON.parse(r.record);const next=mutate(row);
    await tx.query('UPDATE purchases SET record=$1,state=$2 WHERE id=$3',[canonical(next),next.state,id]);return next;
  });}
  async release(id,owner){await this.driver.query('UPDATE purchases SET lease_owner=NULL,lease_until=0 WHERE id=$1 AND lease_owner=$2',[id,owner]);}
  async finish(id,owner,bytes,event){this.calls++;return this.driver.transaction(async tx=>{
    const [r]=await tx.query('SELECT record,lease_owner,result_bytes FROM purchases WHERE id=$1'+tx.lock,[id]);demand(r,'PURCHASE_NOT_FOUND',404);
    if(r.result_bytes)return r.result_bytes;
    demand(r.lease_owner===owner,'LEASE_LOST',409);const row=JSON.parse(r.record);demand(row.state==='SETTLED','SETTLEMENT_NOT_DURABLE',503);
    row.state='ISSUED';row.result_hash=createHash('sha256').update(bytes).digest('hex');
    await tx.query('INSERT INTO registry_events(purchase_id,sequence,event_bytes,event_hash) VALUES($1,$2,$3,$4)',[id,0,canonical(event),hash(event)]);
    await tx.query('UPDATE purchases SET state=$1,record=$2,result_bytes=$3,lease_owner=NULL,lease_until=0 WHERE id=$4',['ISSUED',canonical(row),bytes,id]);
    return bytes;
  });}
  async events(id){const rows=await this.driver.query('SELECT event_bytes FROM registry_events WHERE purchase_id=$1 ORDER BY sequence',[id]);return rows.map(r=>JSON.parse(r.event_bytes));}
  async appendEvent(id,make){return this.driver.transaction(async tx=>{
    const [p]=await tx.query('SELECT state FROM purchases WHERE id=$1'+tx.lock,[id]);demand(p&&p.state==='ISSUED','PURCHASE_NOT_ISSUED',409);
    const rows=await tx.query('SELECT event_bytes,event_hash,sequence FROM registry_events WHERE purchase_id=$1 ORDER BY sequence DESC LIMIT 1',[id]);
    const last=rows[0], event=make(last?JSON.parse(last.event_bytes):null,last?last.sequence+1:0,last?last.event_hash:null);
    await tx.query('INSERT INTO registry_events(purchase_id,sequence,event_bytes,event_hash) VALUES($1,$2,$3,$4)',[id,event.payload.sequence,canonical(event),hash(event)]);return event;
  });}
  async review(record){return this.driver.transaction(async tx=>{await tx.query('INSERT INTO review_requests(review_id,purchase_id,record) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[record.review_id,record.purchase_id,canonical(record)]);const [saved]=await tx.query('SELECT record FROM review_requests WHERE review_id=$1',[record.review_id]);const prior=JSON.parse(saved.record);demand(hash(prior.request)===hash(record.request),'REVIEW_IDEMPOTENCY_CONFLICT',409);return prior;});}
  async close(){await this.driver.close();}
}

export async function sqliteStore(filename) {
  const {DatabaseSync}=await import('node:sqlite');const db=new DatabaseSync(filename);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
  // Serialize complete transactions within this connection, including awaited callbacks.
  let queue=Promise.resolve();
  const query=async(sql,params=[])=>{const bound=[];const normalized=sql.replace(/\$(\d+)/g,(_,n)=>{bound.push(params[Number(n)-1]);return '?';});const st=db.prepare(normalized);return st.columns().length?st.all(...bound): (st.run(...bound),[]);};
  const serialize=fn=>{const p=queue.then(fn,fn);queue=p.catch(()=>{});return p;};
  const driver={script:sql=>serialize(()=>db.exec(sql)),query:(sql,p)=>serialize(()=>query(sql,p)),
    transaction:fn=>serialize(async()=>{db.exec('BEGIN IMMEDIATE');try{const result=await fn({query,lock:''});db.exec('COMMIT');return result;}catch(e){db.exec('ROLLBACK');throw e;}}),
    close:()=>serialize(()=>db.close())};
  const store=new Store(driver);await store.initialize();return store;
}

// Separate, durable multi-instance production backend. Requires the pinned optional pg dependency.
// Never selects SQLite or /tmp as a production fallback.
export async function postgresStore(connectionString) {
  demand(typeof connectionString==='string'&&connectionString.startsWith('postgres'),'DATABASE_URL_REQUIRED',503);
  const {default:pg}=await import('pg');const pool=new pg.Pool({connectionString,max:4,connectionTimeoutMillis:5000,query_timeout:10000});
  const query=async(sql,params=[])=> (await pool.query(sql,params)).rows;
  const driver={script:sql=>pool.query(sql),query,transaction:async fn=>{
    const c=await pool.connect();try{await c.query('BEGIN');const r=await fn({query:async(sql,p)=>(await c.query(sql,p)).rows,lock:' FOR UPDATE'});await c.query('COMMIT');return r;}
    catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}},close:()=>pool.end()};
  // DDL is an explicit migration step, not performed during a request.
  return new Store(driver);
}
export {migration};
