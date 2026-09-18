// All HTTP and MCP acquisition now share the same public, signature-free transport.
export async function mcpRoute(service,req){const {publicMachineRoute}=await import('./public-machine.mjs');return publicMachineRoute(service,req);}
