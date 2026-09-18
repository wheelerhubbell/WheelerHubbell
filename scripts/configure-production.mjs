// Current project, existing database, existing payment semantics. No authority establishment.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {canonical,parseStrict,demand,hash,publicDer,keyId} from '../src/canonical.mjs';
import {validateTrust} from '../src/authority.mjs';
import {postgresStore,migration} from '../src/store.mjs';
import {livePaymentDestination} from '../src/discovery.mjs';
import {api,target,variable,put,value,ORIGIN,exportTarget,verifySourceCommitments} from './netlify-production-target.mjs';
import {readApprovedPublicAuthority} from './open-authority-administration.mjs';

export const PAYMENT_REQUIREMENTS={scheme:'exact',network:'eip155:8453',amount:'1000000',asset:'0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',payTo:'0x1050eddd8282623b0c263ed6bdbd42370bbc28d3',maxTimeoutSeconds:300,extra:{assetTransferMethod:'eip3009',paymentFlow:'authorization',name:'USD Coin',version:'2'}};
const tables=['purchases','registry_events','review_requests'];
const required={purchases:{id:['text','NO'],buyer_key:['text','NO'],client_reference:['text','NO'],request_hash:['text','NO'],state:['text','NO'],payment_key:['text','YES'],record:['text','NO'],result_bytes:['text','YES'],lease_owner:['text','YES'],lease_until:['bigint','NO']},registry_events:{purchase_id:['text','NO'],sequence:['integer','NO'],event_bytes:['text','NO'],event_hash:['text','NO']},review_requests:{review_id:['text','NO'],purchase_id:['text','NO'],record:['text','NO']}};
const metadata=async q=>q("SELECT table_name,column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' AND table_name=ANY($1::text[]) ORDER BY table_name,ordinal_position",[tables]);
function checkColumns(rows,complete){
 for(const name of tables){const cols=rows.filter(r=>r.table_name===name);if(!cols.length&&!complete)continue;for(const [col,[type,nullable]] of Object.entries(required[name])){const got=cols.find(r=>r.column_name===col);demand(got&&got.data_type===type&&got.is_nullable===nullable,'DATABASE_STRUCTURE_MISMATCH_'+name+'_'+col);}}
 const lease=rows.find(r=>r.table_name==='purchases'&&r.column_name==='lease_until');if(lease)demand(/^'?0'?(?:::bigint)?$/.test(lease.column_default??''),'DATABASE_LEASE_DEFAULT_MISMATCH');
}
export async function inspectExistingDatabase(site){
 const db=await api('/sites/'+site.id+'/database?role=netlifydb_owner');demand(typeof db.connection_string==='string','EXISTING_DATABASE_CONNECTION_REQUIRED');
 const store=await postgresStore(db.connection_string);try{
  let rows=await metadata(store.driver.query);checkColumns(rows,false);const missing=tables.filter(n=>!rows.some(r=>r.table_name===n));let applied=false;
  if(missing.length){const bytes=await readFile('netlify/database/migrations/0001_whp_standing.sql','utf8');demand(bytes===migration,'EXISTING_MIGRATION_SOURCE_MISMATCH');await store.driver.transaction(async tx=>{await tx.query("SELECT pg_advisory_xact_lock(hashtext('whp-standing-schema-v1'))");const locked=await metadata(tx.query);checkColumns(locked,false);if(tables.some(n=>!locked.some(r=>r.table_name===n))){await tx.query(bytes);applied=true;}});}
  rows=await metadata(store.driver.query);checkColumns(rows,true);
  const constraints=await store.driver.query("SELECT r.relname AS table_name,c.contype,pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND r.relname=ANY($1::text[])",[tables]);
  const norm=x=>x.replaceAll('public.','').replace(/\s+/g,' ').trim();
  for(const [table,defs] of Object.entries({purchases:['PRIMARY KEY (id)','UNIQUE (payment_key)','UNIQUE (buyer_key, client_reference)'],registry_events:['PRIMARY KEY (purchase_id, sequence)','FOREIGN KEY (purchase_id) REFERENCES purchases(id)'],review_requests:['PRIMARY KEY (review_id)','FOREIGN KEY (purchase_id) REFERENCES purchases(id)']}))for(const def of defs)demand(constraints.some(c=>c.table_name===table&&norm(c.definition)===def),'DATABASE_CONSTRAINT_MISMATCH_'+table);
  return {provider:'Netlify managed PostgreSQL',existing_connection_verified:true,required_tables:tables,column_structure_verified:true,required_constraints_verified:true,existing_migration_applied:applied,customer_rows_read:false,database_created:false,database_replaced:false,runtime_role_connection_not_yet_observed:true};
 }finally{await store.close();}
}
export async function configureProduction(){
 const commitments=await verifySourceCommitments(),site=await target();await exportTarget(site);const pub=await readApprovedPublicAuthority();
 const [rootRow,issuerRow,bundleRow]=await Promise.all(['WHP_ROOT_PIN','WHP_ISSUER_PRIVATE_KEY','WHP_TRUST_BUNDLE_JSON'].map(k=>variable(site,k)));
 const issuer=value(issuerRow),bundle=parseStrict(value(bundleRow),1048576);
 demand(value(rootRow)===pub.root_pin&&keyId(publicDer(issuer))===pub.issuer_key_id&&hash(bundle)===hash(pub.trust_bundle),'AUTHORITY_CONFIGURATION_MISMATCH');
 const trust=validateTrust(bundle,pub.root_pin,Math.floor(Date.now()/1000));demand(trust.profile.environment==='LIVE','LIVE_AUTHORITY_REQUIRED');
 livePaymentDestination(PAYMENT_REQUIREMENTS);
 const database=await inspectExistingDatabase(site);
 const configuration={WHP_USE_NETLIFY_DATABASE:'true',WHP_ORIGIN:ORIGIN,WHP_FACILITATOR_URL:'https://facilitator.payai.network',WHP_RPC_URL:'https://base-rpc.publicnode.com',WHP_PAYMENT_REQUIREMENTS_JSON:canonical(PAYMENT_REQUIREMENTS),WHP_RESOLUTION_URL:ORIGIN+'/.well-known/standing-capability.json',WHP_CAPABILITY_CATALOG_URL:ORIGIN+'/discovery/provider-index.json'};
 for(const [k,v] of Object.entries(configuration))await put(site,k,v);for(const [k,v] of Object.entries(configuration))demand(value(await variable(site,k))===v,'CONFIG_READBACK_FAILED_'+k);
 const report={checked_at:new Date().toISOString(),source_commit:process.env.GITHUB_SHA??null,origin:ORIGIN,site_id:site.id,commitments,root_pin:pub.root_pin,issuer_key_id:pub.issuer_key_id,authority_configuration_agrees:true,v11_authority_verified:true,database,payment_requirements:PAYMENT_REQUIREMENTS,payment_semantics_changed:false,configuration_ready_for_deployment:true,deployed_runtime_observed:false,account_plan_changed:false,payment_executed:false};
 await mkdir('evidence/production',{recursive:true});await writeFile('evidence/production/configuration.json',JSON.stringify(report,null,2)+'\n');return report;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{console.log(JSON.stringify(await configureProduction()));}catch(e){console.error('PRODUCTION_CONFIGURATION_STOPPED',e.code??'SAFE_INTERNAL_FAILURE');process.exitCode=1;}}
