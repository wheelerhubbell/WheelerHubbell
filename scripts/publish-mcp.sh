#!/usr/bin/env bash
set -euo pipefail
# Run only under the authenticated repository's release workflow after public LIVE checks.
# No independent npm package is claimed or needed for the actually deployed remote transport.
node scripts/check-public-service.mjs
python3 - <<'PY'
import urllib.request,json,hashlib,pathlib,tarfile,io,re
url='https://api.github.com/repos/modelcontextprotocol/registry/releases/latest'
with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'WHPStanding-registry-publisher'}),timeout=30) as r:release=json.load(r)
version=release['tag_name'];m=re.search(r'(\d+)\.(\d+)\.(\d+)',version)
assert m and tuple(map(int,m.groups()))>=(1,7,6),'Old publisher vulnerable to OIDC audience replay'
asset=next(a for a in release['assets'] if a['name']=='mcp-publisher_linux_amd64.tar.gz')
digest=asset.get('digest','');assert digest.startswith('sha256:'),'Release must expose independently recorded asset digest'
with urllib.request.urlopen(asset['browser_download_url'],timeout=60) as r:data=r.read(30_000_001)
assert len(data)<=30_000_000 and 'sha256:'+hashlib.sha256(data).hexdigest()==digest
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
    entry=next(m for m in t.getmembers() if m.name in ['mcp-publisher','./mcp-publisher'])
    assert entry.isfile();binary=t.extractfile(entry).read()
p=pathlib.Path('.runtime/mcp-publisher');p.parent.mkdir(exist_ok=True);p.write_bytes(binary);p.chmod(0o700)
pathlib.Path('evidence/public-service/publisher-release.json').write_text(json.dumps({'release':version,'asset':asset['name'],'digest':digest,'source':release['html_url']},indent=2)+'\n')
PY
.runtime/mcp-publisher validate evidence/public-service/server.json
.runtime/mcp-publisher login github-oidc --registry=https://registry.modelcontextprotocol.io
trap '.runtime/mcp-publisher logout >/dev/null 2>&1 || true' EXIT
.runtime/mcp-publisher publish evidence/public-service/server.json | tee evidence/public-service/mcp-publish.txt
python3 - <<'PY'
import urllib.request,json,pathlib,datetime
name='io.github.wheelerhubbell/whp-standing';metadata=json.loads(pathlib.Path('evidence/public-service/server.json').read_text())
url='https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.wheelerhubbell%2Fwhp-standing'
with urllib.request.urlopen(url,timeout=30) as r:data=json.load(r)
matching=[x for x in data.get('servers',[]) if x.get('server',{}).get('name')==name and x['server'].get('version')==metadata['version'] and x['server'].get('remotes')==metadata['remotes']]
assert matching,'Publish response alone is not registry read-back evidence'
pathlib.Path('evidence/public-service/mcp-registration.json').write_text(json.dumps({'state':'REGISTERED','checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'registry':url,'accepted_records':matching},indent=2)+'\n')
PY
