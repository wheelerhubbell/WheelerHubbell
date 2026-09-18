import {createServer} from 'node:http';
import {pathToFileURL} from 'node:url';

export function nodeServer(service){return createServer({maxHeaderSize:24576},async(req,res)=>{
  try{
    const body=[];let size=0;for await(const part of req){size+=part.length;if(size>262144){res.writeHead(413,{'content-type':'application/json'});res.end('{"error":{"code":"BODY_TOO_LARGE"}}');return;}body.push(part);}
    const method=req.method??'GET';const headers=new Headers();for(let i=0;i<req.rawHeaders.length;i+=2)headers.append(req.rawHeaders[i],req.rawHeaders[i+1]);
    const request=new Request(service.origin+(req.url??'/'),{method,headers,...(!['GET','HEAD'].includes(method)?{body:Buffer.concat(body)}:{})});
    const response=await service.handle(request);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
  }catch{res.writeHead(503,{'content-type':'application/json','cache-control':'no-store'});res.end('{"error":{"code":"SERVICE_UNAVAILABLE"}}');}
});}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const {runtimeFromEnvironment}=await import('./runtime.mjs');const service=await runtimeFromEnvironment();const server=nodeServer(service);
  server.listen(Number(process.env.PORT??8080),'0.0.0.0');
  const close=()=>server.close(async()=>{await service.store.close();process.exit(0);});process.on('SIGTERM',close);process.on('SIGINT',close);
}
