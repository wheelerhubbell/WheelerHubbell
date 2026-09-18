// Publish the existing reference buyer and its runtime closure, without server keys or fixtures.
import {readFile,mkdir,writeFile,mkdtemp,copyFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {gzipSync} from 'node:zlib';
import {hashBytes,canonical,demand} from '../src/canonical.mjs';
import {VERIFIER_HASH} from '../src/protocol.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const files=['scripts/buy.mjs','src/buyer.mjs','src/buyer-journal.mjs','src/canonical.mjs',
  'src/authority.mjs','src/namespace-authority.mjs','src/validation.mjs','src/payment.mjs','src/keccak.mjs','src/profile.mjs','src/protocol.mjs',
  'profiles/structured-passage-1.1.0.json','public/contract.json','public/verifier-manifest.json',
  'verify/python-verifier.mjs','verify/verify_mark.py','public/buyer/README.md'];
const staging=await mkdtemp(join(tmpdir(),'whp-buyer-package-'));
try{
  const hashes={};
  for(const file of files){const bytes=await readFile(join(root,file));hashes[file]=hashBytes(bytes);
    await mkdir(dirname(join(staging,file)),{recursive:true});await copyFile(join(root,file),join(staging,file));}
  demand(hashes['verify/verify_mark.py']===VERIFIER_HASH,'FROZEN_VERIFIER_BYTES_MISMATCH');
  await writeFile(join(staging,'package.json'),canonical({name:'whp-standing-reference-buyer',private:true,type:'module',engines:{node:'>=22.16.0'}})+'\n');
  // Stable archive bytes make the discovery commitment reproducible across builds.
  const tar=execFileSync('tar',['--sort=name','--mtime=@0','--owner=0','--group=0','--numeric-owner','--format=ustar','-cf','-','-C',staging,'.']);
  const archive=gzipSync(tar,{level:9}),path='/buyer/standing-buyer.tar.gz';
  const manifest={name:'StandingBuyer',version:'WHP-STANDING-REFERENCE-BUYER-v1.1',path,sha256:hashBytes(archive),
    source_files:hashes,runtime:{node:'>=22.16.0',python:'>=3.11',python_packages:['cryptography','jsonschema'],node_install_required:false},
    command:'node scripts/buy.mjs POLICY.json SUBMISSION.json OWNER_PROVIDER.mjs JOURNAL.sqlite OUTPUT.json',
    owner_inputs:['admitted root and pinned payment policy','exact signed submission with stable cryptographically random 256-bit client_reference and authority evidence','existing owner-authorized EIP-1193 wallet provider','persistent journal','independently trusted HTTPS chain RPC'],
    environment_variables:['WHP_BUYER_RPC_URL','WHP_BUYER_MAX_WAIT_SECONDS (optional)'],
    buyer_authentication_signature_required:false,compatibility:'Standard x402 v2 exact EIP-3009 with client-selected random nonce; this package is an optional reference client.'};
  await writeFile(join(root,'public'+path),archive);
  await writeFile(join(root,'public/buyer/manifest.json'),canonical(manifest)+'\n');
  console.log(JSON.stringify({path,sha256:manifest.sha256,files:files.length}));
}finally{await rm(staging,{recursive:true,force:true});}
