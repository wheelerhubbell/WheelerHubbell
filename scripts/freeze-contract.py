#!/usr/bin/env python3
"""Build public-v1 commitments. --check verifies without rewriting any file."""
import base64,hashlib,json,re,subprocess,sys,zlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def canonical(x):
    if isinstance(x,dict):return '{'+','.join(canonical(k)+':'+canonical(x[k]) for k in sorted(x,key=lambda k:k.encode('utf-16be'))) + '}'
    if isinstance(x,list):return '['+','.join(canonical(v) for v in x)+']'
    return json.dumps(x,ensure_ascii=False,separators=(',',':'))
def h(x):return hashlib.sha256(x).hexdigest()
def load(p):return json.loads((R/p).read_text())
check='--check' in sys.argv
profile=load('profiles/structured-passage-1.1.0.json');schemas={k:load('schemas/'+v+'.schema.json') for k,v in [('result','result'),('resolution','discovery-resolution')]}
manifest={**load('contracts/manifest-template.json'),'schema_sha256':h(canonical(schemas['result']).encode())}
ch=h(canonical(manifest).encode());ph=h(canonical(profile).encode())
code=(R/'verify/verify_mark.py').read_text()
code=re.sub(r"^PROFILE_HASH = .*",'PROFILE_HASH = '+repr(ph),code,flags=re.M)
code=re.sub(r"^CONTRACT_HASH = .*",'CONTRACT_HASH = '+repr(ch),code,flags=re.M)
code=re.sub(r"^WIRE_SCHEMAS_B64 = .*",'WIRE_SCHEMAS_B64 = '+repr(base64.b64encode(zlib.compress(canonical(schemas).encode(),9)).decode()),code,flags=re.M)
source_hash=h(code.encode());path='/verification/'+source_hash+'.py'
values={'public/contract.json':json.dumps(manifest,ensure_ascii=False,indent=2)+'\n','verify/verify_mark.py':code,'public/verifier-manifest.json':json.dumps({'sha256':source_hash,'path':path,'contract_hash':ch,'schema_sha256':manifest['schema_sha256']},indent=2)+'\n','public'+path:code}
# Historical hash-addressed verifier files remain immutable and publicly available.
for name,text in values.items():
    p=R/name
    if check:assert p.is_file() and p.read_text()==text,'UNFROZEN_CONTRACT: '+name
    else:p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
print(json.dumps({'contract_sha256':ch,'profile_sha256':ph,'schema_sha256':manifest['schema_sha256'],'verifier_sha256':source_hash,'checked_without_writes':check},indent=2))
