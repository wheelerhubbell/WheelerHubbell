import {postgresStore} from '../src/store.mjs';
const db=await postgresStore(process.env.DATABASE_URL);
try{await db.initialize();console.log('WHP Standing schema migration completed.');}finally{await db.close();}
