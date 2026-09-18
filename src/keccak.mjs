// Keccak-256 for public EVM event IDs / function selectors only. Payment and issuer
// signature verification are NOT implemented with this helper.
const MASK=(1n<<64n)-1n;
const RC=[1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
const R=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]];
const rot=(x,n)=>n===0?x:((x<<BigInt(n))|(x>>BigInt(64-n)))&MASK;
function permutation(a){for(const rc of RC){const c=Array(5).fill(0n),d=[];for(let x=0;x<5;x++)for(let y=0;y<5;y++)c[x]^=a[x+5*y];for(let x=0;x<5;x++)d[x]=c[(x+4)%5]^rot(c[(x+1)%5],1);for(let x=0;x<5;x++)for(let y=0;y<5;y++)a[x+5*y]^=d[x];const b=Array(25).fill(0n);for(let x=0;x<5;x++)for(let y=0;y<5;y++)b[y+5*((2*x+3*y)%5)]=rot(a[x+5*y],R[x][y]);for(let x=0;x<5;x++)for(let y=0;y<5;y++)a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);a[0]^=rc;}}
export function keccak(data){const b=Buffer.isBuffer(data)?data:Buffer.from(data);const p=Buffer.alloc(Math.ceil((b.length+1)/136)*136);b.copy(p);p[b.length]=1;p[p.length-1]|=128;const a=Array(25).fill(0n);for(let off=0;off<p.length;off+=136){for(let j=0;j<17;j++)a[j]^=p.readBigUInt64LE(off+j*8);permutation(a);}const out=Buffer.alloc(32);for(let j=0;j<4;j++)out.writeBigUInt64LE(a[j],j*8);return '0x'+out.toString('hex');}
