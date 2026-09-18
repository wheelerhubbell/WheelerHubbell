// Deterministic candidate-source commitment. It excludes execution evidence and
// renewable root publications; it is an orchestrator record, not remote attestation.
import {readFile,readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join,resolve} from 'node:path';
import {hash,hashBytes,demand} from '../src/canonical.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const directories=['src','schemas','profiles','verify','netlify/functions','legacy/v1/src','public/immutable','public/verification'];
const files=['package.json','package-lock.json','netlify.toml','requirements.txt','requirements-verification.txt',
  'contracts/manifest-template.json','public/contract.json','public/verifier-manifest.json','public/openapi.json',
  'public/examples/submission.TEST.json','public/buyer/manifest.json',
  'scripts/cold-purchaser.mjs','scripts/run-live-chain.mjs','scripts/check-live-chain.mjs','scripts/release-source.mjs',
  'scripts/public-artifact-sandbox.py','scripts/check-activation.mjs','scripts/check-deployment.mjs','scripts/package-buyer.mjs',
  'scripts/freeze-contract.py','scripts/generate-schemas.py','scripts/check-schemas.py',
  'scripts/open-authority-administration.mjs','scripts/netlify-production-target.mjs',
  'scripts/observe-authority-deployment.mjs','.github/workflows/deploy-production.yml'];

export async function releaseSource(directory=root){
  const base=resolve(directory),paths=[...files];
  async function visit(relative){
    for(const entry of await readdir(join(base,relative),{withFileTypes:true})){
      const path=relative+'/'+entry.name;
      if(entry.name==='__pycache__'||entry.name.endsWith('.pyc'))continue;
      demand(!entry.isSymbolicLink(),'RELEASE_SOURCE_SYMLINK_FORBIDDEN');
      if(entry.isDirectory())await visit(path);else if(entry.isFile())paths.push(path);
    }
  }
  for(const directory of directories)await visit(directory);
  const manifest={version:'WHP-RELEASE-SOURCE-v1',files:await Promise.all(paths.sort().map(async path=>({path,sha256:hashBytes(await readFile(join(base,path)))})))};
  return {...manifest,sha256:hash(manifest)};
}
