import {sqliteStore} from '../../src/store.mjs';
const [file,id]=process.argv.slice(2);const store=await sqliteStore(file);
try{const row=await store.get(id);if(!row?.result_bytes)throw Error('MISSING_DURABLE_RESULT');process.stdout.write(row.result_bytes);}finally{await store.close();}
