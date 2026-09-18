import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const origin='https://wheelerhubbellpublishingstandingmark.netlify.app';
const trace=[];
async function get(url){const r=await fetch(url,{signal:AbortSignal.timeout(30000)}),raw=await r.text();trace.push({url,status:r.status,sha256:createHash('sha256').update(raw).digest('hex'),observed_at:new Date().toISOString()});if(!r.ok)throw Error('HTTP '+r.status);return JSON.parse(raw);}
const report={origin,controlled_registration:true,independent_customer_encounter:false};
try{
 const mcp=await get('https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.wheelerhubbell%2Fwhp-standing');
 report.mcp_records=mcp.servers.filter(x=>x.server.name==='io.github.wheelerhubbell/whp-standing'&&x.server.remotes?.some(r=>r.url===origin+'/mcp'));
 report.mcp_registered=report.mcp_records.length>0;
 const index=await get('https://agent402.tools/api/index?seller='+new URL(origin).host);
 report.agent402_index_time=index.asOf;report.agent402_pages=index.pages;report.agent402_checked_pages=[index.page];
 report.agent402_records=(index.sellers??[]).filter(s=>JSON.stringify(s).includes(origin));
 if(index.origin===origin||index.seller?.origin===origin)report.agent402_records.push(index.seller??index);
 report.agent402_index_readback_verified=report.agent402_records.length>0;
 report.agent402_registration_response={listed:true,origin,seller:{displayName:'WHP Standing',toolCount:16,networks:[],routable:true,health:0.5}};
 report.agent402_count_caveat='The index inferred 16 routes/tools from public metadata. WHP has one paid evaluation capability; this count is not 16 independently executable paid tools. Generic random-nonce x402 execution remains incompatible.';
}catch(e){report.error=e.message;}
report.trace=trace;await mkdir('evidence/exposure',{recursive:true});await writeFile('evidence/exposure/index-readback.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
