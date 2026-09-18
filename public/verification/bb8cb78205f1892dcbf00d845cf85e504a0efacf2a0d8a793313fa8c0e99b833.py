#!/usr/bin/env python3
"""Independent WHP Standing verifier. Imports no producer modules.
Requires Python >=3.11 and cryptography. Never treats an embedded root as trust.
Offline validity, current registry standing and chain settlement are separate outputs.
"""
import argparse, base64, hashlib, json, re, sys, time, urllib.request, urllib.parse, zlib
from jsonschema import Draft202012Validator
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE_HASH = '4244be9ed0012eaeba8e2efeb9d274ad3c1f3e188748838c191129054d24c5ab'
CONTRACT_HASH = 'dd433c055fe0ad0bdb0326479b3339eea018204ccef44cd6ef247520a29c8e75'
WIRE_SCHEMAS_B64 = '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'
OPS = ['INFORM', 'RECOMMEND', 'EXECUTE']

def schemas(): return json.loads(zlib.decompress(base64.b64decode(WIRE_SCHEMAS_B64)))
def shape(value, name): Draft202012Validator(schemas()[name]).validate(value)

def need(value, code):
    if not value: raise ValueError(code)

def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out

def canonical(x, depth=0):
    need(depth <= 64, 'JSON_DEPTH')
    if x is None: return 'null'
    if isinstance(x, bool): return 'true' if x else 'false'
    if isinstance(x, int):
        need(abs(x) <= 9007199254740991, 'INTEGER_RANGE')
        return str(x)
    if isinstance(x, str):
        need(not any(0xD800 <= ord(c) <= 0xDFFF for c in x), 'INVALID_UNICODE')
        return json.dumps(x, ensure_ascii=False, separators=(',', ':'))
    if isinstance(x, list): return '[' + ','.join(canonical(v, depth+1) for v in x) + ']'
    need(isinstance(x, dict), 'I_JSON_REQUIRED')
    return '{' + ','.join(canonical(k,depth+1)+':'+canonical(x[k],depth+1) for k in sorted(x,key=lambda k:k.encode('utf-16be'))) + '}'

def digest(x): return hashlib.sha256(canonical(x).encode()).hexdigest()
def bytehash(x): return hashlib.sha256(x).hexdigest()
def read(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 2_000_000, 'FILE_TOO_LARGE')
    x = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                   parse_int=lambda n: int(n) if n != '-0' else (_ for _ in ()).throw(ValueError('NEGATIVE_ZERO_NOT_ALLOWED')),
                   parse_float=lambda _: (_ for _ in ()).throw(ValueError('FLOAT_NOT_ALLOWED')),
                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_NOT_ALLOWED')))
    canonical(x)
    return x, raw

def exact(x, fields): need(isinstance(x,dict) and set(x)==set(fields), 'FIELDS_INVALID')
def keyid(pub): return bytehash(base64.b64decode(pub,validate=True))
def unseal(e, kind, pub):
    exact(e,['protected','payload','signature'])
    exact(e['protected'],['type','algorithm','canonicalization','key_id'])
    need(e['protected']=={'type':kind,'algorithm':'Ed25519','canonicalization':'WHP-JCS-I1','key_id':keyid(pub)}, 'SIGNATURE_CONTEXT')
    der=base64.b64decode(pub,validate=True);need(base64.b64encode(der).decode()==pub,'PUBLIC_KEY_ENCODING');k=load_der_public_key(der)
    need(isinstance(k,Ed25519PublicKey) and k.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==der,'ED25519_REQUIRED')
    sig=base64.b64decode(e['signature'],validate=True); need(len(sig)==64 and base64.b64encode(sig).decode()==e['signature'],'SIGNATURE_LENGTH_OR_ENCODING')
    k.verify(sig,canonical({'protected':e['protected'],'payload':e['payload']}).encode())
    return e['payload']

def trust(bundle,pin,at):
    need(len(canonical(bundle).encode())<=65536,'TRUST_BUNDLE_TOO_LARGE')
    Draft202012Validator({'$defs':schemas()['result']['$defs'],'$ref':'#/$defs/trust_bundle'}).validate(bundle)
    exact(bundle,['root_public_key','profile_authorization','certificates','revocations','status_snapshot'])
    root=bundle['root_public_key']; need(keyid(root)==pin,'UNTRUSTED_ROOT')
    pa=unseal(bundle['profile_authorization'],'WHP-PROFILE-AUTHORIZATION-v1',root)
    exact(pa,['profile_hash','contract_hash','verifier_sha256','ratified','issuer','environment','valid_from','valid_until'])
    need(pa['profile_hash']==PROFILE_HASH and pa['contract_hash']==CONTRACT_HASH and pa['verifier_sha256']==bytehash(Path(__file__).read_bytes()) and pa['ratified'] is True and pa['valid_from']<=at<pa['valid_until'],'PROFILE_NOT_AUTHORIZED')
    need(pa['environment'] in ['LIVE','TEST'],'ENVIRONMENT_INVALID')
    status=unseal(bundle['status_snapshot'],'WHP-TRUST-STATUS-v1',root)
    exact(status,['sequence','previous_hash','profile_authorization_hash','certificates_hash','revocations_hash','valid_from','valid_until'])
    need(status['valid_from']<=at<status['valid_until'],'TRUST_STATUS_EXPIRED')
    need(status['profile_authorization_hash']==digest(bundle['profile_authorization']) and status['certificates_hash']==digest(bundle['certificates']) and status['revocations_hash']==digest(bundle['revocations']),'TRUST_STATUS_MANIFEST_MISMATCH')
    keys={}
    for e in bundle['certificates']:
        c=unseal(e,'WHP-AUTHORITY-CERTIFICATE-v1',root)
        exact(c,['public_key','subject','roles','scopes','jurisdictions','operations','profile_hash','valid_from','valid_until'])
        need(c['profile_hash']==PROFILE_HASH,'CERTIFICATE_PROFILE')
        kid=keyid(c['public_key']); need(kid not in keys,'DUPLICATE_AUTHORITY');keys[kid]=c
    rev=[unseal(e,'WHP-KEY-REVOCATION-v1',root) for e in bundle['revocations']]
    return pa,keys,rev

def grant(e,kind,role,ctx,keys,rev,at):
    c=keys[e['protected']['key_id']]
    unseal(e,kind,c['public_key'])
    need(role in c['roles'],'ROLE_NOT_AUTHORIZED')
    need(ctx['scope'] in c['scopes'] and ctx['jurisdiction'] in c['jurisdictions'],'AUTHORITY_OUT_OF_BOUNDS')
    need(c['valid_from']<=at<c['valid_until'],'AUTHORITY_EXPIRED')
    need(not any(r['key_id']==e['protected']['key_id'] and r['effective_at']<=at for r in rev),'AUTHORITY_REVOKED')
    need(all(op in c['operations'] for op in ctx.get('operations',[])),'AUTHORITY_OPERATION_DENIED')
    return c

def input_shape(s):
    # Independently enforce the closed structural contract; bool is NOT an integer.
    canonical(s,16)
    exact(s,['version','client_reference','buyer_key','profile','object','bounds','requested_operation','nodes','transitions'])
    def text(v):need(isinstance(v,str) and 0<len(v.encode('utf-16be'))//2<=4096,'TEXT_REQUIRED')
    def integer(v):need(type(v) is int and 0<=v<=9007199254740991,'INTEGER_REQUIRED')
    def window(v):integer(v['valid_from']);integer(v['valid_until']);need(v['valid_until']>v['valid_from'],'INVALID_TIME_WINDOW')
    def array(v,maximum=128):need(isinstance(v,list) and len(v)<=maximum,'ARRAY_INVALID')
    def unique(v):need(len({canonical(x) for x in v})==len(v),'DUPLICATE_ITEM')
    def operations(v):array(v,3);unique(v);need(all(x in OPS for x in v),'OPERATION_INVALID')
    def hashed(v):need(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) is not None,'HASH_INVALID')
    need(re.fullmatch('[A-Za-z0-9_-]{16,96}',s['client_reference']) is not None,'CLIENT_REFERENCE_INVALID')
    der=base64.b64decode(s['buyer_key'],validate=True);key=load_der_public_key(der)
    need(isinstance(key,Ed25519PublicKey) and key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==der,'INVALID_BUYER_KEY')
    exact(s['object'],['id','version','root']);text(s['object']['id']);text(s['object']['version']);hashed(s['object']['root'])
    exact(s['bounds'],['scope','jurisdiction','valid_from','valid_until']);text(s['bounds']['scope']);text(s['bounds']['jurisdiction']);window(s['bounds'])
    array(s['nodes'],64);array(s['transitions'],64)
    for e in s['nodes']:
        x=e['payload'];exact(x,['id','version','content','locator','epistemic_status','qualifiers','unknowns','operations','scope','jurisdiction','valid_from','valid_until','status','prior_hash'])
        for k in ['id','version','locator','scope','jurisdiction']:text(x[k])
        window(x);operations(x['operations']);array(x['qualifiers']);unique(x['qualifiers'])
        for q in x['qualifiers']:text(q)
        array(x['unknowns'],64);unique(x['unknowns']);unique([u['id'] for u in x['unknowns']])
        for u in x['unknowns']:exact(u,['id','description','blocks']);text(u['id']);text(u['description']);operations(u['blocks'])
        if x['prior_hash'] is not None:hashed(x['prior_hash'])
        need(x['epistemic_status'] in ['OBSERVATION','REPORT','FINDING','INFERENCE','HYPOTHESIS','UNKNOWN'] and x['status'] in ['ACTIVE','CORRECTED','SUPERSEDED','DISPUTED','WITHDRAWN'],'SOURCE_ENUM_INVALID')
    for e in s['transitions']:
        t=e['payload'];exact(t,['from','to','transform','operations','scope','jurisdiction','valid_from','valid_until','warrant']);array(t['from'],64);unique(t['from']);hashed(t['to'])
        for h in t['from']:hashed(h)
        window(t);operations(t['operations']);text(t['scope']);text(t['jurisdiction']);exact(t['warrant'],['statement','evidence_hashes']);text(t['warrant']['statement']);array(t['warrant']['evidence_hashes'],64);unique(t['warrant']['evidence_hashes'])
        for h in t['warrant']['evidence_hashes']:hashed(h)

def assess(s,bundle,pin,at,profile):
    input_shape(s)
    exact(s,['version','client_reference','buyer_key','profile','object','bounds','requested_operation','nodes','transitions'])
    need(s['version']=='WHP-STANDING-SUBMISSION-v1','SUBMISSION_VERSION')
    need(s['profile']=={'id':profile['id'],'version':profile['version'],'sha256':PROFILE_HASH},'SUBMISSION_PROFILE')
    need(s['requested_operation'] in OPS and 0<len(s['nodes'])<=64 and len(s['transitions'])<=64,'SUBMISSION_LIMITS')
    pa,keys,rev=trust(bundle,pin,at)
    checks=[]
    def check(rule,obj,passed): checks.append([rule,obj,bool(passed)])
    n={digest(e['payload']):e for e in s['nodes']}
    need(len(n)==len(s['nodes']),'DUPLICATE_NODES')
    need(len({(e['payload']['id'],e['payload']['version']) for e in s['nodes']})==len(n),'DUPLICATE_VERSIONS')
    edges={e['payload']['to']:e for e in s['transitions']}; need(len(edges)==len(s['transitions']),'MULTIPLE_INCOMING_WARRANTS')
    root=n.get(s['object']['root'],{}).get('payload')
    check('SOURCE_IDENTITY',s['object']['root'],root and root['id']==s['object']['id'] and root['version']==s['object']['version'])
    b=s['bounds'];check('ASSESSMENT_TIME',s['object']['root'],b['valid_from']<=at<b['valid_until'])
    expiry=min(b['valid_until'],pa['valid_until'],at+profile['max_validity_seconds']); allowed=set(OPS)
    for h,e in n.items():
        x=e['payload']
        exact(x,['id','version','content','locator','epistemic_status','qualifiers','unknowns','operations','scope','jurisdiction','valid_from','valid_until','status','prior_hash'])
        try:
            c=grant(e,'WHP-SOURCE-ATTESTATION-v1','SOURCE',{**b,'operations':x['operations']},keys,rev,at)
            check('SOURCE_AUTHORITY',h,c['valid_from']<=b['valid_from'] and b['valid_until']<=c['valid_until']);expiry=min(expiry,c['valid_until'])
        except Exception: check('SOURCE_AUTHORITY',h,False)
        check('SOURCE_ACTIVE',h,x['status']=='ACTIVE')
        check('SOURCE_BOUNDS',h,x['scope']==b['scope'] and x['jurisdiction']==b['jurisdiction'])
        check('SOURCE_TIME',h,x['valid_from']<=b['valid_from'] and b['valid_until']<=x['valid_until']);expiry=min(expiry,x['valid_until'])
        allowed.intersection_update(x['operations'])
        for u in x['unknowns']: allowed.difference_update(u['blocks'])
    seen=set();visiting=set();invalid=[False]
    def visit(h):
        if h in visiting or h not in n: invalid[0]=True;return
        if h in seen:return
        visiting.add(h)
        if h in edges:
            for ph in edges[h]['payload']['from']:visit(ph)
        visiting.remove(h);seen.add(h)
    visit(s['object']['root'])
    check('GRAPH_CLOSURE',s['object']['root'],not invalid[0] and len(seen)==len(n) and all(h in n for h in edges))
    for e in s['transitions']:
        t=e['payload'];h=digest(t)
        exact(t,['from','to','transform','operations','scope','jurisdiction','valid_from','valid_until','warrant'])
        need(len(t['from'])>0 and len(t['from'])==len(set(t['from'])) and t['transform'] in ['COPY','COMPOSE'],'TRANSITION_SHAPE')
        try:
            c=grant(e,'WHP-TRANSITION-WARRANT-v1','TRANSITION',{**b,'operations':t['operations']},keys,rev,at)
            check('TRANSITION_AUTHORITY',h,c['valid_from']<=b['valid_from'] and b['valid_until']<=c['valid_until']);expiry=min(expiry,c['valid_until'])
        except Exception:check('TRANSITION_AUTHORITY',h,False)
        check('TRANSITION_BOUNDS',h,t['scope']==b['scope'] and t['jurisdiction']==b['jurisdiction'] and t['valid_from']<=b['valid_from'] and b['valid_until']<=t['valid_until'])
        expiry=min(expiry,t['valid_until']);allowed.intersection_update(t['operations'])
        check('WARRANT_EVIDENCE',h,bool(t['warrant']['evidence_hashes']) and all(x in n for x in t['warrant']['evidence_hashes']))
        target=n.get(t['to'],{}).get('payload');parents=[n.get(ph,{}).get('payload') for ph in t['from']]
        if not target or any(p is None for p in parents):check('TRANSITION_REFERENCES',h,False);continue
        if t['transform']=='COPY':
            ok=len(parents)==1 and canonical(target['content'])==canonical(parents[0]['content']) and target['epistemic_status']==parents[0]['epistemic_status']
        else:
            ok=canonical(target['content'])==canonical({'kind':'COMPOSE','members':[{'hash':ph,'content':n[ph]['payload']['content']} for ph in sorted(t['from'])]}) and target['epistemic_status']=='REPORT'
        check('EXACT_TRANSFORMATION',h,ok)
        check('QUALIFIERS_PRESERVED',h,all(q in target['qualifiers'] for p in parents for q in p['qualifiers']))
        check('UNKNOWNS_PRESERVED',h,all(u in target['unknowns'] for p in parents for u in p['unknowns']))
        check('NO_FORCE_ESCALATION',h,all(op in t['operations'] and all(op in p['operations'] for p in parents) for op in target['operations']))
    check('REQUESTED_OPERATION',s['object']['root'],s['requested_operation'] in allowed)
    ok=all(c[2] for c in checks)
    components={k:('ESTABLISHED' if ok else 'NOT_ESTABLISHED') for k in ['SOURCE','CONTEXT','UNKNOWN']}
    components.update({k:(('ESTABLISHED' if ok else 'NOT_ESTABLISHED') if s['transitions'] else 'NOT_ASSESSED') for k in ['RELATION','PASSAGE']})
    components.update({'CONTINUITY':'NOT_ASSESSED','ACTION_BOUNDARY':'NOT_ASSESSED'})
    return ok,[op for op in OPS if op in allowed] if ok else [],checks,max(0,expiry),components

def verify_result(e,pin,allow_test=False):
    shape(e,'result')
    p=e['payload']
    need(p['protocol']['sha256']==CONTRACT_HASH==digest(p['protocol']['document']),'PUBLIC_CONTRACT_MISMATCH')
    need(p['protocol']['verifier_sha256']==bytehash(Path(__file__).read_bytes()),'VERIFIER_SOURCE_MISMATCH')
    need(p['protocol']['document']['schema_sha256']==digest(schemas()['result']),'RESULT_SCHEMA_COMMITMENT')
    exact(p,['version','environment','issuer','issuer_key_id','purchase_id','mark_id','issued_at','effective_at','expires_at','object','profile','profile_authorization','authority','submission','submission_hash','decision_record','decision_record_ref','standing','commerce','retrieval','limitations','current_status_rule','discovery','protocol'])
    need(p['version']=='WHP-STANDING-RESULT-v1','RESULT_VERSION')
    need(p['environment']=='LIVE' or (allow_test and p['environment']=='TEST'),'TEST_ARTIFACT_NOT_LIVE')
    need(p['environment']!='LIVE' or p['issuer']=='Wheeler Hubbell Publishing','LIVE_ISSUER_IDENTITY')
    need(digest(p['profile'])==PROFILE_HASH,'PROFILE_CONTENT_MISMATCH')
    pa,keys,rev=trust(p['authority'],pin,p['issued_at'])
    need(pa['environment']==p['environment'] and pa['issuer']==p['issuer'] and p['profile_authorization']==p['authority']['profile_authorization'],'ISSUER_AUTHORIZATION_MISMATCH')
    c=grant(e,e['protected']['type'],'ISSUER',p['submission']['bounds'],keys,rev,p['issued_at'])
    need(p['issuer_key_id']==e['protected']['key_id'],'ISSUER_KEY_MISMATCH')
    s=p['submission'];d=p['decision_record']
    exact(d,['version','evaluated_at','submission_hash','object','profile','bounds','requested_operation','outcome','permitted_operations','components','effective_at','expires_at','checks','unknowns','assessment_boundary','not_assessed','review_triggers']);need(d['version']=='WHP-STANDING-DECISION-v1','DECISION_VERSION')
    need(digest(s)==p['submission_hash']==d['submission_hash'],'SUBMISSION_HASH_MISMATCH')
    need(p['decision_record_ref']=='urn:sha256:'+digest(d),'DECISION_RECORD_HASH')
    need(p['object']==s['object']==d['object'] and d['profile']==s['profile'] and d['bounds']==s['bounds'] and d['requested_operation']==s['requested_operation'],'DECISION_BINDING')
    need(d['evaluated_at']<=p['issued_at'] and p['effective_at']==d['effective_at']==d['evaluated_at'],'ASSESSMENT_TIME_BINDING')
    ok,ops,checks,expiry,components=assess(s,p['authority'],pin,d['evaluated_at'],p['profile'])
    need(d['outcome']==('ESTABLISHED' if ok else 'NOT_ESTABLISHED') and d['permitted_operations']==ops,'EVALUATION_REPLAY_MISMATCH')
    need([[r['rule'],r['object'],r['passed']] for r in d['checks']]==checks,'CHECK_TRACE_REPLAY_MISMATCH')
    need(d['components']==components and d['expires_at']==expiry and p['expires_at']==min(expiry,c['valid_until']),'STANDING_OR_EXPIRY_MISMATCH')
    need(d['unknowns']==[{'source_hash':digest(e['payload']),'unknowns':e['payload']['unknowns']} for e in s['nodes']],'UNKNOWNS_MISMATCH')
    need(p['limitations']==d['not_assessed']==p['profile']['not_assessed'] and d['assessment_boundary']==p['profile']['assessed'] and d['review_triggers']==p['profile']['review_triggers'],'ASSESSMENT_CEILING_MISMATCH')
    pid=digest({'domain':'WHP-STANDING-PURCHASE-v1','root_pin':pin,'buyer_key':s['buyer_key'],'client_reference':s['client_reference']})
    need(pid==p['purchase_id'],'PURCHASE_ID_MISMATCH')
    need(p['mark_id']==('WHP-SM-'+pid if ok else None),'MARK_ID_MISMATCH')
    need(e['protected']['type']==('WHP-STANDING-MARK-v1' if ok else 'WHP-STANDING-ASSESSMENT-v1'),'INVALID_MARK_PROMOTION')
    need(p['standing']==({'operation':s['requested_operation'],'components':components,'bounds':s['bounds']} if ok else None),'STANDING_BINDING')
    co=p['commerce'];exact(co,['quote','payment_identity','payment_payload','settlement','assessment_paid_by','relationship','assessor']);q=co['quote'];qp=unseal(q,'WHP-STANDING-QUOTE-v1',c['public_key'])
    exact(qp,['purchase_id','request_hash','buyer_key','profile_hash','issuer','environment','issued_at','expires_at','resource','payment_requirements','charge_policy'])
    need(qp['purchase_id']==pid and qp['request_hash']==digest(s) and qp['buyer_key']==s['buyer_key'] and qp['profile_hash']==PROFILE_HASH and qp['issuer']==p['issuer'] and qp['environment']==p['environment'],'QUOTE_BINDING')
    pay=co['payment_payload'];a=pay['payload']['authorization'];r=pay['accepted'];settle=co['settlement']
    expected_relationship='Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.' if p['environment']=='TEST' else 'The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.'
    need(co['relationship']==expected_relationship,'PAYMENT_RELATIONSHIP_ENVIRONMENT')
    need(qp['issued_at']<=d['evaluated_at']<qp['expires_at'] and qp['expires_at']>qp['issued_at'],'QUOTE_TIME_BINDING')
    need(int(a['validAfter'])<=d['evaluated_at']<int(a['validBefore']),'PAYMENT_AUTHORIZATION_TIME')
    if p['environment']=='LIVE':
        need(r['network']=='eip155:8453' and r['asset']=='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' and r['payTo']=='0x1050eddd8282623b0c263ed6bdbd42370bbc28d3' and r['extra']['name']=='USD Coin' and r['extra']['version']=='2','LIVE_PAYMENT_DESTINATION')
    need(pay['x402Version']==2 and r==qp['payment_requirements'] and pay['resource']==qp['resource'],'PAYMENT_TERMS_MISMATCH')
    nonce='0x'+digest({'domain':'WHP-STANDING-PURCHASE-BINDING-v1','quote':qp})
    need(a['nonce'].lower()==nonce and a['to'].lower()==r['payTo'].lower() and a['value']==r['amount'],'PAYMENT_PURCHASE_BINDING')
    identity=digest({'domain':'WHP-EIP3009-PAYMENT-IDENTITY-v1','network':r['network'],'asset':r['asset'].lower(),'authorizer':a['from'].lower(),'nonce':nonce})
    need(co['payment_identity']==identity and co['assessment_paid_by']==a['from'],'PAYMENT_IDENTITY_MISMATCH')
    for name,val in [('environment',p['environment']),('network',r['network']),('asset',r['asset']),('payer',a['from']),('pay_to',a['to']),('amount',a['value']),('nonce',a['nonce'])]: need(settle[name]==val,'SETTLEMENT_BINDING_'+name)
    need(re.fullmatch(r'0x[0-9a-f]{64}',settle['transaction']) is not None,'TRANSACTION_ID_INVALID')
    need(p['retrieval']=={'purchase_path':'/v1/purchases/'+pid,'result_path':'/v1/purchases/'+pid+'/result','registry_path':'/v1/registry/'+pid,'authentication':'Buyer Ed25519 proof bound to HTTP method, path and body','additional_charge':False},'RETRIEVAL_BINDING')
    verify_discovery(p)
    return {'verified':True,'cryptographic_integrity':'VERIFIED','evaluation_replay':'VERIFIED','environment':p['environment'],'purchase_id':pid,'mark_id':p['mark_id'],'assessment':d['outcome'],'current_standing':'NOT_CHECKED','payment_chain_finality':'NOT_RECHECKED' if p['environment']=='LIVE' else 'SIMULATED_NOT_LIVE','expires_at':p['expires_at']}


def verify_discovery(p):
    x=p['discovery'];u=urllib.parse.urlsplit(x['resolution_url'])
    exact(x,['version','capability_id','capability_class','resolution_id','resolution_url','root_key_id','status_id'])
    need(x['version']=='WHP-STANDING-DISCOVERY-IDENTITY-v1' and x['capability_id']=='urn:whp:standing:capability:1' and x['capability_class']=='urn:capability:machine-verifiable-standing:1' and x['resolution_id']=='urn:whp:standing:resolution:1','DISCOVERY_IDENTITY')
    need(u.scheme=='https' or p['environment']=='TEST' and u.scheme=='http' and u.hostname=='127.0.0.1','RESOLUTION_ORIGIN')
    need(u.netloc and not u.username and not u.password and not u.query and not u.fragment,'RESOLUTION_LOCATION')
    need(x['root_key_id']==keyid(p['authority']['root_public_key']),'DISCOVERY_ROOT_BINDING')
    need(x['status_id']=='urn:whp:standing:status:'+p['purchase_id'],'STATUS_ID_BINDING')

def verify_resolution(snapshot,result,pin,at):
    shape(snapshot,'resolution');sp=snapshot['payload'];p=result['payload'];x=p['discovery']
    pa,keys,rev=trust(sp['trust_bundle'],pin,at)
    grant(snapshot,'WHP-CAPABILITY-RESOLUTION-v1','DISCOVERY',sp['authority_context'],keys,rev,at)
    need(sp['observed_at']<=at+30 and at<sp['valid_until']<=sp['observed_at']+300,'RESOLUTION_STALE')
    need(sp['valid_until']<=sp['trust_bundle']['status_snapshot']['payload']['valid_until'],'RESOLUTION_TRUST_FRESHNESS')
    need(all(sp[k]==x[k] for k in ['capability_id','capability_class','resolution_id','root_key_id']),'RESOLUTION_IDENTITY')
    need(sp['environment']==p['environment']==pa['environment'] and sp['issuer']==pa['issuer'],'RESOLUTION_ENVIRONMENT_OR_ISSUER')
    origin=urllib.parse.urlsplit(sp['service_origin'])
    need(origin.scheme=='https' or sp['environment']=='TEST' and origin.scheme=='http' and origin.hostname=='127.0.0.1','CURRENT_SERVICE_ORIGIN')
    need(origin.netloc and not origin.username and not origin.password and not origin.query and not origin.fragment and origin.path in ['', '/'],'CURRENT_SERVICE_ORIGIN')
    def same(url):
        u=urllib.parse.urlsplit(url);need((u.scheme,u.netloc)==(origin.scheme,origin.netloc) and not u.username and not u.password and not u.fragment,'CURRENT_SERVICE_LINK')
    for k in ['service_contract','openapi']:same(sp[k]['url'])
    same(sp['registry_template'].replace('{purchase_id}',p['purchase_id']))
    need(sp['registry_template'].count('{purchase_id}')==1,'REGISTRY_TEMPLATE')
    wanted={'PROFILE':PROFILE_HASH,'CONTRACT':CONTRACT_HASH,'SCHEMA':p['protocol']['document']['schema_sha256'],'VERIFIER':p['protocol']['verifier_sha256']}
    for kind,h in wanted.items():
        matches=[a for a in sp['artifacts'] if a['kind']==kind and a['sha256']==h];need(len(matches)==1,'IMMUTABLE_ARTIFACT_UNRESOLVED_'+kind);same(matches[0]['url'])
    return {'verified':True,'resolution_id':sp['resolution_id'],'capability_id':sp['capability_id'],'service_origin':sp['service_origin'],'observed_at':sp['observed_at'],'valid_until':sp['valid_until']}

def verify_resolution_only(snapshot,document,pin,allow_test,at):
    need(digest(document)==CONTRACT_HASH,'CONTRACT_COMMITMENT')
    need(document['schema_sha256']==digest(schemas()['result']),'SCHEMA_COMMITMENT')
    sp=snapshot['payload'];need(allow_test or sp['environment']=='LIVE','TEST_ARTIFACT_NOT_LIVE')
    # Provider discovery is not a historical assessment. No synthetic standing is inferred.
    context={'payload':{'discovery':{k:sp[k] for k in ['capability_id','capability_class','resolution_id','root_key_id']},
        'environment':sp['environment'],'purchase_id':'catalog-discovery',
        'protocol':{'document':document,'verifier_sha256':bytehash(Path(__file__).read_bytes())}}}
    result=verify_resolution(snapshot,context,pin,at)
    return {**result,'environment':sp['environment'],'historical_issuance':'NOT_PRESENT',
        'current_standing':'NOT_CHECKED','institutional_root_admission':'CALLER_SUPPLIED_PIN_REQUIRED',
        'live_completion_verified':False}

def verify_registry(snapshot,result,raw_result,pin,at):
    p=result['payload'];sp=snapshot['payload'];exact(sp,['purchase_id','result_hash','mark_id','status','observed_at','valid_until','events','trust_bundle']);pa,keys,rev=trust(sp['trust_bundle'],pin,at)
    grant(snapshot,'WHP-REGISTRY-SNAPSHOT-v1','REGISTRY',p['submission']['bounds'],keys,rev,at)
    need(sp['observed_at']<=at+30 and at<sp['valid_until']<=sp['observed_at']+300,'REGISTRY_SNAPSHOT_STALE')
    need(sp['purchase_id']==p['purchase_id'] and sp['result_hash']==bytehash(raw_result) and sp['mark_id']==p['mark_id'],'REGISTRY_RESULT_BINDING')
    previous=None;last=None
    for i,e in enumerate(sp['events']):
        ep=e['payload'];exact(ep,['purchase_id','sequence','previous_hash','result_hash','mark_id','status','at','reason','command']);grant(e,'WHP-REGISTRY-EVENT-v1','REGISTRY',p['submission']['bounds'],keys,rev,ep['at'])
        need(ep['sequence']==i and ep['previous_hash']==previous and ep['purchase_id']==p['purchase_id'] and ep['result_hash']==sp['result_hash'] and ep['mark_id']==p['mark_id'],'REGISTRY_CHAIN_INVALID')
        if i==0:need(ep['status']==('ACTIVE' if p['mark_id'] else 'ASSESSED_NO_MARK') and ep['command'] is None,'REGISTRY_ORIGIN_INVALID')
        else:
            cp=unseal(ep['command'],'WHP-REGISTRY-COMMAND-v1',sp['trust_bundle']['root_public_key'])
            need(cp['expected_previous_hash']==previous and cp['purchase_id']==ep['purchase_id'] and cp['status']==ep['status'] and cp['reason']==ep['reason'] and cp['at']==ep['at'],'REGISTRY_COMMAND_BINDING')
            need(last['status'] not in ['WITHDRAWN','SUPERSEDED'] and ep['at']>=last['at'],'REGISTRY_TRANSITION_INVALID')
        previous=digest(e);last=ep
    need(last is not None,'REGISTRY_EMPTY')
    expected='EXPIRED' if last['status']=='ACTIVE' and at>=p['expires_at'] else last['status']
    if expected=='ACTIVE':
        try:
            grant(result,result['protected']['type'],'ISSUER',p['submission']['bounds'],keys,rev,at)
            for source in p['submission']['nodes']:grant(source,'WHP-SOURCE-ATTESTATION-v1','SOURCE',{**p['submission']['bounds'],'operations':source['payload']['operations']},keys,rev,at)
            for edge in p['submission']['transitions']:grant(edge,'WHP-TRANSITION-WARRANT-v1','TRANSITION',{**p['submission']['bounds'],'operations':edge['payload']['operations']},keys,rev,at)
        except Exception:expected='LIMITED'
    need(sp['status']==expected,'REGISTRY_STATUS_MISMATCH')
    return expected

def recheck_chain(p,rpc_url):
    need(rpc_url.startswith('https://'),'HTTPS_RPC_REQUIRED');need(p['environment']=='LIVE','TEST_PAYMENT_HAS_NO_CHAIN_FINALITY')
    pay=p['commerce']['payment_payload'];r=pay['accepted'];a=pay['payload']['authorization'];s=p['commerce']['settlement'];txid=s['transaction']
    def rpc(method,params):
        body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
        req=urllib.request.Request(rpc_url,data=body,headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=15) as f:answer=json.load(f)
        need('error' not in answer,'RPC_ERROR');return answer['result']
    need('eip155:'+str(int(rpc('eth_chainId',[]),16))==r['network'],'RPC_CHAIN_MISMATCH')
    receipt=rpc('eth_getTransactionReceipt',[txid]);tx=rpc('eth_getTransactionByHash',[txid]);head=rpc('eth_getBlockByNumber',['finalized',False])
    need(receipt and tx and head and receipt['status']=='0x1' and int(receipt['blockNumber'],16)<=int(head['number'],16),'SETTLEMENT_NOT_FINALIZED')
    block=rpc('eth_getBlockByNumber',[receipt['blockNumber'],False]);need(block['hash']==receipt['blockHash']==tx['blockHash']==s['block_hash'],'BLOCK_IDENTITY_MISMATCH')
    need(tx['to'].lower()==r['asset'].lower() and tx['hash'].lower()==txid,'WRONG_PAYMENT_TRANSACTION')
    w=lambda n:format(int(n),'064x')
    sig=pay['payload']['signature'][2:].lower();v=int(sig[-2:],16);v=v+27 if v<27 else v
    expected='0xe3ee160e'+a['from'][2:].lower().rjust(64,'0')+a['to'][2:].lower().rjust(64,'0')+w(a['value'])+w(a['validAfter'])+w(a['validBefore'])+a['nonce'][2:].lower()+w(v)+sig[:64]+sig[64:128]
    need(tx['input'].lower()==expected==s['transaction_input'].lower(),'TRANSFER_CALLDATA_MISMATCH')
    topic=lambda addr:'0x'+addr[2:].lower().rjust(64,'0')
    logs=[l for l in receipt['logs'] if l['address'].lower()==r['asset'].lower() and not l.get('removed',False) and l['transactionHash'].lower()==txid and l['blockHash']==receipt['blockHash']]
    auth=[l for l in logs if [x.lower() for x in l['topics']]==['0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5',topic(a['from']),a['nonce'].lower()]]
    transfer=[l for l in logs if [x.lower() for x in l['topics']]==['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topic(a['from']),topic(a['to'])] and int(l['data'],16)==int(a['value'])]
    need(len(auth)==1 and len(transfer)==1,'PAYMENT_EVENT_IDENTITY_MISMATCH')
    return 'FINALIZED_RECHECKED_AGAINST_SUPPLIED_RPC'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('mark');parser.add_argument('--root-pin',required=True);parser.add_argument('--allow-test',action='store_true');parser.add_argument('--registry');parser.add_argument('--at',type=int);parser.add_argument('--rpc');parser.add_argument('--resolution');parser.add_argument('--resolution-only',action='store_true');parser.add_argument('--contract')
    args=parser.parse_args()
    try:
        e,raw=read(args.mark)
        if args.resolution_only:
            need(args.contract is not None,'IMMUTABLE_CONTRACT_REQUIRED')
            report=verify_resolution_only(e,read(args.contract)[0],args.root_pin,args.allow_test,args.at or int(time.time()))
            print(json.dumps(report,indent=2));return 0
        report=verify_result(e,args.root_pin,args.allow_test)
        report['historical_issuance']='VERIFIED';report['institutional_root_admission']='CALLER_SUPPLIED_PIN_REQUIRED'
        if args.resolution:report['current_discovery']=verify_resolution(read(args.resolution)[0],e,args.root_pin,args.at or int(time.time()))
        if args.registry:report['current_standing']=verify_registry(read(args.registry)[0],e,raw,args.root_pin,args.at or int(time.time()))
        if args.rpc:report['payment_chain_finality']=recheck_chain(e['payload'],args.rpc)
        report['technical_live_issuance_verified']=report['environment']=='LIVE' and report['mark_id'] is not None and report['current_standing']=='ACTIVE' and report['payment_chain_finality']=='FINALIZED_RECHECKED_AGAINST_SUPPLIED_RPC'
        report['outside_buyer_relationship']='NOT_ESTABLISHED_BY_THIS_VERIFIER';report['live_completion_verified']=False
        print(json.dumps(report,indent=2));return 0
    except Exception as error:
        partial=locals().get('report',{});partial.update({'verified':False,'error':str(error) or type(error).__name__,'live_completion_verified':False})
        if partial.get('historical_issuance')=='VERIFIED':partial['current_standing']='NOT_VERIFIED'
        print(json.dumps(partial));return 1
if __name__=='__main__':sys.exit(main())
