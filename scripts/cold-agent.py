#!/usr/bin/env python3
"""Generic public signed-artifact/capability reader. One input, no provider configuration.
The input is a signed artifact, a neutral object/action/interface, or their ordered join.
Untrusted downloaded verification code runs only in a networkless read-only OCI sandbox.
This program has no wallet key and never authorizes or settles a payment.
"""
import base64,hashlib,json,os,pathlib,secrets,subprocess,sys,tempfile,time,urllib.request,urllib.error,urllib.parse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,load_der_public_key
from jsonschema import Draft202012Validator

def need(value,message):
    if not value:raise ValueError(message)
def pairs(items):
    out={}
    for k,v in items:need(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
    return out
def canon(x,depth=0):
    need(depth<=64,'JSON_DEPTH')
    if x is None:return 'null'
    if isinstance(x,bool):return 'true' if x else 'false'
    if isinstance(x,int):need(abs(x)<=9007199254740991,'INTEGER_RANGE');return str(x)
    if isinstance(x,str):
        need(not any(0xd800<=ord(c)<=0xdfff for c in x),'UNICODE');return json.dumps(x,ensure_ascii=False,separators=(',',':'))
    if isinstance(x,list):return '['+','.join(canon(v,depth+1) for v in x)+']'
    need(isinstance(x,dict),'INTEGER_JSON_REQUIRED')
    return '{'+','.join(canon(k,depth+1)+':'+canon(x[k],depth+1) for k in sorted(x,key=lambda s:s.encode('utf-16be')))+'}'
def integer(token):need(token!='-0','NEGATIVE_ZERO');return int(token)
def parse(raw):
    result=json.loads(raw,object_pairs_hook=pairs,parse_int=integer,parse_float=lambda _:(_ for _ in ()).throw(ValueError('FLOAT_NOT_ALLOWED')))
    canon(result);return result
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(x):return sha(canon(x).encode())
def b64(raw):
    v=base64.b64decode(raw,validate=True);need(base64.b64encode(v).decode()==raw,'NONCANONICAL_BASE64');return v
def pointer(obj,p):
    need(isinstance(p,str) and (not p or p.startswith('/')),'JSON_POINTER')
    for k in p.split('/')[1:]:
        k=k.replace('~1','/').replace('~0','~');obj=obj[int(k)] if isinstance(obj,list) else obj[k]
    return obj
def signature(envelope,pub,recipe,kind=None):
    need(set(envelope)=={'protected','payload','signature'},'SIGNED_ENVELOPE')
    h=envelope['protected'];need(set(h)=={'type','algorithm','canonicalization','key_id'},'PROTECTED_FIELDS')
    need(h['algorithm']==recipe['algorithm']=='Ed25519','SIGNATURE_ALGORITHM')
    need(h['canonicalization']==recipe['canonicalization'],'CANONICALIZATION_CONTEXT')
    if kind:need(h['type']==kind,'SIGNATURE_TYPE')
    der=b64(pub);key=load_der_public_key(der);need(isinstance(key,Ed25519PublicKey),'KEY_ALGORITHM')
    need(key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==der,'CANONICAL_DER')
    need(sha(der)==h['key_id'],'SIGNING_KEY_ID')
    key.verify(b64(envelope['signature']),canon({k:envelope[k] for k in recipe['signed_fields']}).encode())
    return envelope['payload']
def crypto_recipe(document):
    e=document['envelope'];need(e['signed_fields']==['protected','payload'],'SIGNATURE_INPUT')
    return {'algorithm':e['algorithm'],'canonicalization':document['canonicalization']['id'],'signed_fields':e['signed_fields']}
def bootstrap_trust(bundle,document,program_hash,pin,at):
    root=bundle['root_public_key'];need(sha(b64(root))==pin,'ROOT_SUBSTITUTION')
    b=document['bootstrap'];r=crypto_recipe(document)
    pa=signature(bundle['profile_authorization'],root,r,b['authorization_type'])
    need(pa['contract_hash']==digest(document) and pa['verifier_sha256']==program_hash and pa['profile_hash']==document['profile']['sha256'],'ROOT_AUTHORIZED_CONTRACT')
    need(pa['ratified'] is True and pa['valid_from']<=at<pa['valid_until'],'ROOT_AUTHORIZATION_TIME')
    need(pa['environment']=='TEST','INDEPENDENT_INSTITUTIONAL_ROOT_ADMISSION_REQUIRED')
    status=signature(bundle['status_snapshot'],root,r,b['trust_status_type'])
    need(status['valid_from']<=at<status['valid_until'],'TRUST_STALE')
    for field,source in [('profile_authorization_hash','profile_authorization'),('certificates_hash','certificates'),('revocations_hash','revocations')]:need(status[field]==digest(bundle[source]),'TRUST_MANIFEST')
    keys={}
    for cert in bundle['certificates']:
        c=signature(cert,root,r,b['certificate_type']);kid=sha(b64(c['public_key']));need(kid not in keys,'DUPLICATE_AUTHORITY');need(c['profile_hash']==pa['profile_hash'],'CERTIFICATE_PROFILE');keys[kid]=c
    rev=[signature(e,root,r,b['revocation_type']) for e in bundle['revocations']]
    return {'profile':pa,'keys':keys,'revocations':rev,'recipe':r,'root_pin':pin}
def grant(envelope,trust,role,at,kind=None,scope=None,jurisdiction=None):
    kid=envelope['protected']['key_id'];c=trust['keys'].get(kid);need(c is not None,'SIGNER_UNADMITTED')
    signature(envelope,c['public_key'],trust['recipe'],kind)
    need(role in c['roles'] and c['valid_from']<=at<c['valid_until'],'SIGNER_ROLE_OR_TIME')
    need(not any(x['key_id']==kid and x['effective_at']<=at for x in trust['revocations']),'SIGNER_REVOKED')
    if scope is not None:need(scope in c['scopes'],'SIGNER_SCOPE')
    if jurisdiction is not None:need(jurisdiction in c['jurisdictions'],'SIGNER_JURISDICTION')
    return c
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('REDIRECT_NOT_ALLOWED')
class Reader:
    def __init__(self):
        self.trace=[];self.allowed=set();self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def admit(self,url):
        u=urllib.parse.urlsplit(url)
        need(u.scheme=='https' or (u.scheme=='http' and u.hostname=='127.0.0.1'),'HTTPS_OR_EXPLICIT_LOOPBACK_TEST_REQUIRED')
        need(u.netloc and not u.username and not u.password and not u.fragment,'URL_INVALID')
        self.allowed.add((u.scheme,u.netloc));return (u.scheme,u.netloc)
    def request(self,url,method='GET',data=None,headers=None):
        u=urllib.parse.urlsplit(url);need((u.scheme,u.netloc) in self.allowed and not u.username and not u.password and not u.fragment,'UNADMITTED_ORIGIN')
        req=urllib.request.Request(url,data=data,headers=headers or {},method=method)
        try:r=self.opener.open(req,timeout=20)
        except urllib.error.HTTPError as e:r=e
        with r:
            body=r.read(2_000_001);need(len(body)<=2_000_000,'RESPONSE_SIZE');self.trace.append({'url':url,'method':method,'status':r.status,'sha256':sha(body)});return r.status,dict(r.headers),body
    def document(self,url,expected=None):
        status,_,raw=self.request(url);need(status==200,'DOCUMENT_UNAVAILABLE:'+str(status));value=parse(raw)
        if expected:need(digest(value)==expected,'DOCUMENT_HASH_SUBSTITUTION')
        return value,raw
    def sandbox(self,code,files,args):
        with tempfile.TemporaryDirectory(prefix='public-artifacts-') as directory:
            d=pathlib.Path(directory);d.chmod(0o755)
            for name,raw in {**files,'verifier.py':code}.items():
                need('/' not in name and not name.startswith('.'),'SANDBOX_FILENAME');p=d/name;p.write_bytes(raw);p.chmod(0o444)
            image='cold-python-crypto:1'
            inspected=subprocess.run(['docker','image','inspect',image,'--format','{{.Id}}'],capture_output=True,text=True,timeout=30)
            need(inspected.returncode==0,'GENERIC_SANDBOX_RUNTIME_REQUIRED')
            command=['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=32','--memory=256m','--cpus=1','--user=65534:65534','--tmpfs=/tmp:rw,noexec,nosuid,size=16m','--mount','type=bind,src='+str(d)+',dst=/input,readonly',image,'python3','-I','/input/verifier.py',*args]
            r=subprocess.run(command,capture_output=True,text=True,timeout=45)
            need(r.returncode==0,'INDEPENDENT_VERIFICATION_FAILED:'+r.stdout[:1500]+r.stderr[:1000]);report=parse(r.stdout);need(report['verified'] is True,'VERIFICATION_FAILED')
            return report,{'image':inspected.stdout.strip(),'network':'none','root_filesystem':'read-only','capabilities':'ALL_DROPPED','uid':65534,'mounts':'PUBLIC_DOWNLOADED_ARTIFACTS_ONLY','producer_source':False,'private_keys':False}
    def resolve(self,url,expected=None,document=None,program_hash=None):
        self.admit(url);envelope,raw=self.document(url);sp=envelope['payload']
        # With a Mark this data is bound by its historical identity. Without one it is a candidate,
        # not admitted institutional authority. Candidate code is still sandboxed and hash checked.
        need(sp['environment']=='TEST','INDEPENDENT_INSTITUTIONAL_ROOT_ADMISSION_REQUIRED')
        if expected:
            for k in ['capability_id','capability_class','resolution_id','root_key_id']:need(sp[k]==expected[k],'RESOLUTION_IDENTITY_SUBSTITUTION')
        locations={}
        for location in sp['artifacts']:
            need(location['kind'] not in locations,'DUPLICATE_IMMUTABLE_KIND');locations[location['kind']]=location
        need(set(locations)=={'PROFILE','CONTRACT','SCHEMA','VERIFIER'},'IMMUTABLE_MATERIAL_INCOMPLETE')
        # New provider candidates require generic HTTPS discovery before a root can be examined.
        # This is never a privilege to sign funds or execute fetched code on the host.
        if document is None:
            self.admit(locations['CONTRACT']['url']);document,_=self.document(locations['CONTRACT']['url'],locations['CONTRACT']['sha256'])
            program_hash=locations['VERIFIER']['sha256']
        pin=expected['root_key_id'] if expected else sp['root_key_id'];now=int(time.time())
        trust=bootstrap_trust(sp['trust_bundle'],document,program_hash,pin,now)
        grant(envelope,trust,document['bootstrap']['resolution_role'],now,document['bootstrap']['resolution_type'],**sp['authority_context'])
        need(sp['issuer']==trust['profile']['issuer'] and sp['environment']==trust['profile']['environment'],'ISSUER_ENVIRONMENT')
        need(sp['observed_at']<=now+30 and now<sp['valid_until']<=sp['observed_at']+300,'RESOLUTION_STALE')
        need(sp['valid_until']<=sp['trust_bundle']['status_snapshot']['payload']['valid_until'],'RESOLUTION_TRUST_FRESHNESS')
        origin=urllib.parse.urlsplit(sp['service_origin']);need(origin.path in ['', '/'] and not origin.query,'CURRENT_SERVICE_ORIGIN')
        current=self.admit(sp['service_origin'])
        for link in [sp['service_contract']['url'],sp['openapi']['url'],sp['registry_template'].replace('{purchase_id}','probe'),*(v['url'] for v in locations.values())]:
            u=urllib.parse.urlsplit(link);need((u.scheme,u.netloc)==current and not u.username and not u.password and not u.fragment,'CURRENT_SERVICE_LINK')
        need(sp['registry_template'].count('{purchase_id}')==1,'REGISTRY_TEMPLATE')
        wanted={'PROFILE':document['profile']['sha256'],'CONTRACT':digest(document),'SCHEMA':document['schema_sha256'],'VERIFIER':program_hash}
        for k,h in wanted.items():need(locations[k]['sha256']==h,'IMMUTABLE_COMMITMENT_SUBSTITUTION')
        profile,_=self.document(locations['PROFILE']['url'],wanted['PROFILE']);resolved_document,_=self.document(locations['CONTRACT']['url'],wanted['CONTRACT']);self.document(locations['SCHEMA']['url'],wanted['SCHEMA'])
        need(resolved_document==document and profile['id']==document['profile']['id'] and profile['version']==document['profile']['version'],'IMMUTABLE_PROFILE_VERSION')
        status,_,code=self.request(locations['VERIFIER']['url']);need(status==200 and sha(code)==program_hash,'VERIFIER_SOURCE_HASH')
        return {'envelope':envelope,'bytes':raw,'payload':sp,'document':document,'program_hash':program_hash,'code':code,'trust':trust,'profile':profile}
    def invocation(self,template,replacements):
        # A signed recipe is not permission for arbitrary interpreter or filesystem arguments.
        allowed={'--root-pin','--registry','--resolution','--allow-test','--resolution-only','--contract'}
        need(isinstance(template,list) and len(template)<=16,'VERIFIER_RECIPE')
        out=[]
        for arg in template:
            if arg in replacements:out.append(replacements[arg])
            else:need(arg in allowed,'UNSAFE_VERIFIER_ARGUMENT');out.append(arg)
        return out
    def verify_mark(self,raw):
        mark=parse(raw);protocol=mark['payload']['protocol'];document=protocol['document'];b=document['bootstrap'];identity=pointer(mark,b['identity_pointer']);bundle=pointer(mark,b['authority_pointer'])
        need(digest(document)==protocol['sha256'],'CONTRACT_HASH')
        trust=bootstrap_trust(bundle,document,protocol['verifier_sha256'],identity['root_key_id'],mark['payload']['issued_at'])
        grant(mark,trust,'ISSUER',mark['payload']['issued_at'],mark['protected']['type'])
        need(pointer(mark,b['authorization_pointer'])==bundle['profile_authorization'],'HISTORICAL_AUTHORIZATION')
        meaning={k:pointer(mark,path) for k,path in document['meaning'].items()}
        need(meaning['establishes'] and meaning['does_not_establish'],'MEANING_BOUNDS_REQUIRED')
        resolved=self.resolve(identity['resolution_url'],identity,document,protocol['verifier_sha256'])
        need(resolved['profile']==pointer(mark,b['profile_pointer']),'EMBEDDED_PROFILE_SUBSTITUTION')
        purchase_id=pointer(mark,b['purchase_id_pointer']);registry_url=resolved['payload']['registry_template'].replace('{purchase_id}',urllib.parse.quote(purchase_id,safe=''))
        _,registry_raw=self.document(registry_url)
        args=self.invocation(b['verifier_arguments']+b['test_arguments'],{'{mark}':'/input/artifact.json','{registry}':'/input/registry.json','{resolution}':'/input/resolution.json','{root_pin}':identity['root_key_id']})
        report,sandbox=self.sandbox(resolved['code'],{'artifact.json':raw,'registry.json':registry_raw,'resolution.json':resolved['bytes']},args)
        need(report['historical_issuance']=='VERIFIED' and report['current_standing']=='ACTIVE' and report['current_discovery']['verified'],'CURRENT_STANDING_NOT_ACTIVE')
        need(report['live_completion_verified'] is False,'TEST_PROMOTED_TO_LIVE')
        return mark,meaning,resolved,report,sandbox
    def purchase_boundary(self,resolved,external,action):
        sp=resolved['payload'];purchase,_=self.document(sp['service_contract']['url'],sp['service_contract']['sha256'])
        need(purchase['capability_id']==sp['capability_id'] and purchase['capability_class']==sp['capability_class'],'SERVICE_CAPABILITY')
        need(purchase['public_contract']['document']==resolved['document'] and purchase['public_contract']['sha256']==digest(resolved['document']) and purchase['public_contract']['verifier_sha256']==resolved['program_hash'],'CURRENT_CONTRACT_SEMANTICS')
        need(purchase['root_pin']==sp['root_key_id'] and purchase['environment']==sp['environment'],'SERVICE_ROOT_OR_ENVIRONMENT')
        api,_=self.document(sp['openapi']['url'],sp['openapi']['sha256']);offer=purchase['purchase'];u=urllib.parse.urlsplit(offer['url'])
        need(offer['method']=='POST' and u.path in api['paths'] and 'post' in api['paths'][u.path],'PUBLISHED_PURCHASE_PATH')
        need(any(x['url'].rstrip('/')==sp['service_origin'].rstrip('/') for x in api['servers']),'OPENAPI_SERVICE_ORIGIN')
        schema,_=self.document(offer['input_schema'],offer['input_schema_sha256'])
        def local_refs(x):
            if isinstance(x,dict):
                if '$ref' in x:need(x['$ref'].startswith('#/'),'NONLOCAL_INPUT_SCHEMA_REFERENCE')
                for v in x.values():local_refs(v)
            elif isinstance(x,list):
                for v in x:local_refs(v)
        local_refs(schema)
        probe=purchase['cold_probe'];need(probe['wallet_signing'] is False and probe['authority_established'] is False,'PROBE_CANNOT_APPOINT_AUTHORITY')
        key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo);now=int(time.time())
        inputs={'object_id':external['id'],'object_version':external['version'],'object_content':external['content'],'scope':action['scope'],'jurisdiction':action['jurisdiction'],'operation':action['operation'],
            'now_minus_1':now-1,'now_plus_60':now+60,'client_reference':secrets.token_hex(32),'public_key':base64.b64encode(pub).decode()}
        def expand(x):
            if isinstance(x,dict):
                if set(x)=={'$input'}:need(x['$input'] in inputs,'UNDEFINED_PROBE_INPUT');return inputs[x['$input']]
                return {k:expand(v) for k,v in x.items()}
            if isinstance(x,list):return [expand(v) for v in x]
            return x
        source={'protected':{**probe['source_protected'],'key_id':sha(pub)},'payload':expand(probe['source_payload'])}
        source['signature']=base64.b64encode(key.sign(canon(source).encode())).decode();inputs['signed_node']=source;inputs['node_hash']=digest(source['payload'])
        submission=expand(probe['submission_template']);Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(submission)
        need(submission['object']['id']==external['id'] and submission['object']['version']==external['version'],'EXTERNAL_OBJECT_IDENTITY')
        need(submission['requested_operation']==action['operation'] and submission['bounds']['scope']==action['scope'] and submission['bounds']['jurisdiction']==action['jurisdiction'],'CONTEMPLATED_ACTION_IDENTITY')
        body=canon(submission).encode();auth=purchase['authentication'];path=u.path+('?' + u.query if u.query else '')
        need(auth['key_algorithm']=='Ed25519' and auth['key_id']=='SHA256-SPKI-DER' and auth['signed_fields']==['protected','payload'],'HTTP_AUTHENTICATION_RECIPE')
        values={'HTTP-method':offer['method'],'URL-path-and-query':path,'SHA256-exact-request-bytes':sha(body),'Unix-seconds':now,'Unix-seconds-plus-120':now+120,'random-16-byte-hex':secrets.token_hex(16)}
        signed={'protected':{**auth['protected'],'key_id':sha(pub)},'payload':{k:values[v] for k,v in auth['payload_fields'].items()}}
        proof={**signed,'signature':base64.b64encode(key.sign(canon(signed).encode())).decode()}
        status,headers,terms_raw=self.request(offer['url'],offer['method'],body,{'Content-Type':offer['content_type'],auth['header']:base64.b64encode(canon(proof).encode()).decode()})
        need(status==402,'PAYMENT_BOUNDARY_NOT_REACHED:'+str(status)+':'+terms_raw.decode()[:1000]);terms=parse(terms_raw);headers={k.lower():v for k,v in headers.items()};payment=purchase['payment']
        need(parse(b64(headers[payment['required_header'].lower()]))==terms,'PAYMENT_HEADER_BINDING')
        quote=pointer(terms,payment['quote_pointer']);grant(quote,resolved['trust'],'ISSUER',now,scope=action['scope'],jurisdiction=action['jurisdiction'])
        need(quote['payload']['request_hash']==sha(body),'QUOTE_INPUT_BINDING')
        need(pointer(terms,payment['requirements_pointer'])==offer['requirements']==quote['payload']['payment_requirements'],'PUBLISHED_PAYMENT_REQUIREMENTS')
        need(quote['payload']['resource']['url']==offer['url'],'PAYMENT_RESOURCE_BINDING')
        return {'payment_status':status,'payment_authorizations_created':0,'wallet_keys_available':False,'payment_terms':terms,'probe_request_hash':sha(body),'external_object':{'id':external['id'],'version':external['version'],'content_sha256':digest(external['content'])},'contemplated_action':action,'probe_authority_established':False,'provider_id':sp['capability_id']}
    def from_mark(self,raw):
        mark,meaning,resolved,verification,sandbox=self.verify_mark(raw)
        provenance=meaning['provenance'];root=meaning['object']['root'];node=next(x['payload'] for x in provenance['nodes'] if digest(x['payload'])==root)
        external={k:node[k] for k in ['id','version','content']};action={**{k:meaning['bounds'][k] for k in ['scope','jurisdiction']},'operation':meaning['operation']}
        boundary=self.purchase_boundary(resolved,external,action)
        return {**boundary,'verified':True,'test':'A','environment':'TEST','artifact_type':mark['protected']['type'],'artifact_name':resolved['document']['artifact_types']['positive_name'],'meaning':meaning,
            'completed_path':['Mark','meaning','historical verification and replay','profile','fresh current status','canonical capability','current discovery','purchase contract','x402 payment boundary'],
            'independent_verifier':verification,'sandbox':sandbox,'root_admission':'TEST_SELF_CONSISTENT_ROOT','mark_sha256':sha(raw)}
    def recognize(self,external,action,interface):
        need(interface['vendor_neutral'] is True and interface['catalog']['interface']=='capability-catalog-v1','VENDOR_NEUTRAL_INTERFACE_REQUIRED')
        e=external.get('standing_evidence');result='NO_STANDING_EVIDENCE'
        if e:
            for field,expected,code in [('authority_established',True,'INSUFFICIENT_AUTHORITY'),('provenance_sufficient',True,'PROVENANCE_INSUFFICIENT'),('qualifications_preserved',True,'QUALIFICATION_PRESERVATION_UNESTABLISHED'),('blocking_unknowns',False,'BLOCKING_UNKNOWN'),('independently_verifiable',True,'INDEPENDENTLY_VERIFIABLE_WARRANT_REQUIRED')]:
                if e.get(field) is not expected:result=code;break
            else:result='SUFFICIENT_STANDING_EVIDENCE' if e.get('object_id')==external['id'] and e.get('object_version')==external['version'] and action['operation'] in e.get('operations',[]) else 'TRANSFORMATION_WARRANT_MISSING'
        requirement={'version':interface['version'],'result':result,'capability_required':interface['capability'],'contemplated_action':action,'recognition_basis':'CALLER_SUPPLIED_EVIDENCE_STATUS_NOT_NEW_AUTHORITY'}
        need(result!='SUFFICIENT_STANDING_EVIDENCE','NO_NEW_CAPABILITY_REQUIRED');return requirement
    def from_need(self,value):
        need(set(value)=={'object','action','need_interface'},'NEUTRAL_INITIAL_INPUT_ONLY');external=value['object'];action=value['action'];interface=value['need_interface'];requirement=self.recognize(external,action,interface)
        catalog=interface['catalog']['url'];self.admit(catalog);u=urllib.parse.urlsplit(catalog);need(not u.query,'CATALOG_INTERFACE_URL')
        requested=interface['capability'];query=urllib.parse.urlencode({'capability_class':requested['id'],'requirements':','.join(requested['requirements']),'scope':action['scope'],'jurisdiction':action['jurisdiction']})
        directory,_=self.document(catalog+'?'+query);need(directory['interface']==interface['catalog']['interface'],'CATALOG_INTERFACE')
        candidates=[c for c in directory['providers'] if c['capability_class']==requested['id'] and all(k in c['properties'] for k in requested['requirements']) and action['scope'] in c['scopes'] and action['jurisdiction'] in c['jurisdictions']]
        need(candidates,'NO_COMPATIBLE_PROVIDER');failures=[]
        for candidate in candidates:
            try:
                resolved=self.resolve(candidate['resolution_url']);sp=resolved['payload'];need(sp['capability_class']==requested['id'],'DISCOVERED_CAPABILITY_CLASS')
                document=resolved['document'];args=self.invocation(document['bootstrap']['resolution_arguments']+document['bootstrap']['test_arguments'],{'{resolution}':'/input/resolution.json','{contract}':'/input/contract.json','{root_pin}':sp['root_key_id']})
                verified,sandbox=self.sandbox(resolved['code'],{'resolution.json':resolved['bytes'],'contract.json':canon(document).encode()},args)
                purchase,_=self.document(sp['service_contract']['url'],sp['service_contract']['sha256'])
                need(all(k in purchase['supported_properties'] for k in requested['requirements']) and action['scope'] in purchase['supported_scopes'] and action['jurisdiction'] in purchase['supported_jurisdictions'],'PROVIDER_CAPABILITY_MISMATCH')
                boundary=self.purchase_boundary(resolved,external,action)
                return {**boundary,'verified':True,'test':'B','environment':'TEST','need':requirement,'catalog_provider_count':len(directory['providers']),'compatible_provider_count':len(candidates),'provider_selection_rule':'CAPABILITY_CLASS_PROPERTIES_SCOPE_JURISDICTION_NOT_NAME','rejected_candidates':failures,
                    'completed_path':['external object and action','neutral need recognition','capability catalog query','compatible provider discovery','signed current resolution','purchase contract','x402 payment boundary'],
                    'independent_resolution_verifier':verified,'sandbox':sandbox,'root_admission':'TEST_SELF_CONSISTENT_ROOT','initial_provider_configuration':False}
            except Exception as error:failures.append({'candidate':candidate.get('id'),'error':str(error)})
        raise ValueError('NO_VERIFIED_COMPATIBLE_PROVIDER:'+json.dumps(failures))
    def run(self,raw):
        value=parse(raw)
        if set(value)=={'first','later'}:
            first_raw=base64.b64decode(value['first'],validate=True);first=self.from_mark(first_raw)
            # The new object/action arrives only after current standing and independent replay.
            need(value['later']['object']['id']!=first['meaning']['object']['id'] or value['later']['action']['operation']!=first['meaning']['operation'],'RECURSIVE_OBJECT_MUST_BE_UNSUPPORTED')
            later=self.from_need(value['later'])
            report={'verified':True,'test':'C','environment':'TEST','first':first,'later':later,'ordering':'FIRST_MARK_VERIFIED_BEFORE_LATER_NEED_DISCOVERY','historical_mark_unchanged':sha(first_raw)==first['mark_sha256'],'payment_status':later['payment_status'],'payment_authorizations_created':0,'wallet_keys_available':False}
        elif set(value)=={'object','action','need_interface'}:report=self.from_need(value)
        else:report=self.from_mark(raw)
        return {**report,'input_files':1,'prior_provider_configuration':False,'repository_imports':False,'trace':self.trace,'PROPAGATION-PROVEN':'TEST','production_completion_claim':False,
            'trust_limit':'Cryptographic self-consistency relative to a discovered TEST root, not institutional admission, open-internet discovery or a sale.'}
if __name__=='__main__':
    try:
        need(len(sys.argv)==2,'ONE_INPUT_REQUIRED');raw=pathlib.Path(sys.argv[1]).read_bytes();need(len(raw)<=2_000_000,'INPUT_SIZE');print(json.dumps(Reader().run(raw),indent=2,ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'verified':False,'error':str(error) or type(error).__name__,'PROPAGATION-PROVEN':False}));sys.exit(1)
