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

PROFILE_HASH = 'd6296b9ea7a2c570c2c0ae98af8385d6f8edee1e869fb0ae9f553c90302303a7'
CONTRACT_HASH = 'ab76d9b6684ed2c2f26c21888d936d3f814dbe4f2357a9bf97fe538f513a200a'
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
    c=keys.get(e['protected']['key_id'])
    if c is None:return namespace_grant(e,kind,role,ctx,keys.get('__namespace__',[]),rev,at)
    unseal(e,kind,c['public_key'])
    need(role in c['roles'],'ROLE_NOT_AUTHORIZED')
    need(scoped(c,ctx['scope'],ctx['jurisdiction'],role),'AUTHORITY_OUT_OF_BOUNDS')
    need(c['valid_from']<=at<c['valid_until'],'AUTHORITY_EXPIRED')
    need(not any(r['key_id']==e['protected']['key_id'] and r['effective_at']<=at for r in rev),'AUTHORITY_REVOKED')
    need(all(op in c['operations'] for op in ctx.get('operations',[])),'AUTHORITY_OPERATION_DENIED')
    return c

def namespace_valid(namespace):
    return isinstance(namespace,str) and re.fullmatch(r'https://github\.com/([a-z0-9][a-z0-9-]{0,38})/([a-z0-9_][a-z0-9_.-]{0,99})',namespace) is not None

def scoped(c,scope,jurisdiction,role):
    return jurisdiction in c['jurisdictions'] and (scope in c['scopes'] or role in ['ISSUER','REGISTRY','DISCOVERY'] and 'github-repository:*' in c['scopes'] and namespace_valid(scope) and jurisdiction=='namespace-control')

def namespace_keys(s,evidence,keys,rev,at):
    need(len(evidence)==len(s['authority'])<=8,'NAMESPACE_EVIDENCE_COUNT')
    need(len({x['namespace'] for x in s['authority']})==len(s['authority']),'DUPLICATE_NAMESPACE')
    grants=[]
    for request,e in zip(s['authority'],evidence):
        c=keys[e['protected']['key_id']]
        need('ISSUER' in c['roles'] and scoped(c,request['namespace'],'namespace-control','ISSUER'),'NAMESPACE_OBSERVER_AUTHORITY')
        p=unseal(e,'WHP-NAMESPACE-OBSERVATION-v1',c['public_key'])
        exact(p,['version','namespace','manifest_raw','manifest_sha256','blob_sha','observed_at'])
        need(p['version']=='WHP-NAMESPACE-OBSERVATION-v1' and type(p['observed_at']) is int,'NAMESPACE_OBSERVATION_INVALID')
        need(p['namespace']==request['namespace'] and namespace_valid(p['namespace']) and p['manifest_sha256']==request['manifest_sha256'],'NAMESPACE_EVIDENCE_BINDING')
        raw=p['manifest_raw'].encode();need(len(raw)<=32768,'NAMESPACE_MANIFEST_SIZE')
        need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==p['blob_sha'],'NAMESPACE_BLOB_MISMATCH')
        m=json.loads(p['manifest_raw'],object_pairs_hook=pairs)
        need(digest(m)==p['manifest_sha256'],'NAMESPACE_MANIFEST_HASH')
        exact(m,['version','namespace','valid_from','valid_until','grants'])
        need(m['version']=='WHP-NAMESPACE-GRANTS-v1' and m['namespace']==p['namespace'],'NAMESPACE_MANIFEST_IDENTITY')
        need(c['valid_from']<=p['observed_at']<=at<c['valid_until'] and at-p['observed_at']<=300 and m['valid_from']<=at<m['valid_until'],'NAMESPACE_EVIDENCE_STALE')
        need(not any(r['key_id']==e['protected']['key_id'] and r['effective_at']<=at for r in rev),'NAMESPACE_OBSERVER_REVOKED')
        need(0<len(m['grants'])<=128 and len({canonical(g) for g in m['grants']})==len(m['grants']),'NAMESPACE_GRANTS_INVALID')
        for g in m['grants']:
            exact(g,['public_key','role','payload_hashes','scope','jurisdiction','operations','valid_from','valid_until'])
            der=base64.b64decode(g['public_key'],validate=True);k=load_der_public_key(der)
            need(isinstance(k,Ed25519PublicKey) and k.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)==der,'NAMESPACE_KEY_INVALID')
            need(g['role'] in ['SOURCE','TRANSITION'] and g['scope']==m['namespace'] and g['jurisdiction']=='namespace-control','NAMESPACE_GRANT_SCOPE')
            need(type(g['valid_from']) is int and type(g['valid_until']) is int and m['valid_from']<=g['valid_from']<g['valid_until']<=m['valid_until'],'NAMESPACE_GRANT_TIME')
            hs=g['payload_hashes'];need(0<len(hs)<=128 and len(set(hs))==len(hs) and all(re.fullmatch('[0-9a-f]{64}',h) for h in hs),'NAMESPACE_GRANT_HASHES')
            need(len(g['operations'])<=3 and len(set(g['operations']))==len(g['operations']) and all(o in OPS for o in g['operations']),'NAMESPACE_GRANT_OPERATIONS')
        grants+=m['grants']
    return {**keys,'__namespace__':grants}

def namespace_grant(e,kind,role,ctx,grants,rev,at):
    matches=[g for g in grants if keyid(g['public_key'])==e['protected']['key_id'] and g['role']==role and g['scope']==ctx['scope'] and g['jurisdiction']==ctx['jurisdiction'] and digest(e['payload']) in g['payload_hashes'] and all(o in g['operations'] for o in ctx.get('operations',[])) and g['valid_from']<=at<g['valid_until']]
    need(matches,'UNKNOWN_AUTHORITY');g=matches[0]
    need(not any(r['key_id']==e['protected']['key_id'] and r['effective_at']<=at for r in rev),'AUTHORITY_REVOKED')
    p=unseal(e,kind,g['public_key'])
    if role=='SOURCE':
        u=urllib.parse.urlsplit(p['locator'])
        need('%' not in p['locator'] and chr(92) not in p['locator'] and p['locator'].startswith(g['scope']+'/') and not u.query and not u.fragment and not u.username and not u.password and all(x not in ['.','..'] for x in u.path.split('/')),'NAMESPACE_SOURCE_LOCATOR')
    return g

def input_shape(s):
    # Independently enforce the closed structural contract; bool is NOT an integer.
    canonical(s,16)
    exact(s,['version','client_reference','authority','profile','object','bounds','requested_operation','nodes','transitions'])
    def text(v):need(isinstance(v,str) and 0<len(v.encode('utf-16be'))//2<=4096,'TEXT_REQUIRED')
    def integer(v):need(type(v) is int and 0<=v<=9007199254740991,'INTEGER_REQUIRED')
    def window(v):integer(v['valid_from']);integer(v['valid_until']);need(v['valid_until']>v['valid_from'],'INVALID_TIME_WINDOW')
    def array(v,maximum=128):need(isinstance(v,list) and len(v)<=maximum,'ARRAY_INVALID')
    def unique(v):need(len({canonical(x) for x in v})==len(v),'DUPLICATE_ITEM')
    def operations(v):array(v,3);unique(v);need(all(x in OPS for x in v),'OPERATION_INVALID')
    def hashed(v):need(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) is not None,'HASH_INVALID')
    need(re.fullmatch('[0-9a-f]{64}',s['client_reference']) is not None,'CLIENT_REFERENCE_INVALID')
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

def assess(s,bundle,pin,at,profile,evidence):
    input_shape(s)
    exact(s,['version','client_reference','authority','profile','object','bounds','requested_operation','nodes','transitions'])
    need(s['version']=='WHP-STANDING-SUBMISSION-v1.1','SUBMISSION_VERSION')
    need(s['profile']=={'id':profile['id'],'version':profile['version'],'sha256':PROFILE_HASH},'SUBMISSION_PROFILE')
    need(s['requested_operation'] in OPS and 0<len(s['nodes'])<=64 and len(s['transitions'])<=64,'SUBMISSION_LIMITS')
    pa,keys,rev=trust(bundle,pin,at)
    keys=namespace_keys(s,evidence,keys,rev,at)
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
    exact(p,['version','environment','issuer','issuer_key_id','purchase_id','mark_id','issued_at','effective_at','expires_at','object','profile','profile_authorization','authority','authority_evidence','submission','submission_hash','decision_record','decision_record_ref','standing','commerce','retrieval','limitations','current_status_rule','discovery','protocol'])
    need(p['version']=='WHP-STANDING-RESULT-v1.1','RESULT_VERSION')
    need(p['environment']=='LIVE' or (allow_test and p['environment']=='TEST'),'TEST_ARTIFACT_NOT_LIVE')
    need(p['environment']!='LIVE' or p['issuer']=='Wheeler Hubbell Publishing','LIVE_ISSUER_IDENTITY')
    need(digest(p['profile'])==PROFILE_HASH,'PROFILE_CONTENT_MISMATCH')
    pa,keys,rev=trust(p['authority'],pin,p['issued_at'])
    need(pa['environment']==p['environment'] and pa['issuer']==p['issuer'] and p['profile_authorization']==p['authority']['profile_authorization'],'ISSUER_AUTHORIZATION_MISMATCH')
    c=grant(e,e['protected']['type'],'ISSUER',p['submission']['bounds'],keys,rev,p['issued_at'])
    need(p['issuer_key_id']==e['protected']['key_id'],'ISSUER_KEY_MISMATCH')
    s=p['submission'];d=p['decision_record']
    exact(d,['version','evaluated_at','submission_hash','object','profile','bounds','requested_operation','outcome','permitted_operations','components','effective_at','expires_at','checks','unknowns','assessment_boundary','not_assessed','review_triggers']);need(d['version']=='WHP-STANDING-DECISION-v1.1','DECISION_VERSION')
    need(digest(s)==p['submission_hash']==d['submission_hash'],'SUBMISSION_HASH_MISMATCH')
    need(p['decision_record_ref']=='urn:sha256:'+digest(d),'DECISION_RECORD_HASH')
    need(p['object']==s['object']==d['object'] and d['profile']==s['profile'] and d['bounds']==s['bounds'] and d['requested_operation']==s['requested_operation'],'DECISION_BINDING')
    need(d['evaluated_at']<=p['issued_at'] and p['effective_at']==d['effective_at']==d['evaluated_at'],'ASSESSMENT_TIME_BINDING')
    ok,ops,checks,expiry,components=assess(s,p['authority'],pin,d['evaluated_at'],p['profile'],p['authority_evidence'])
    need(d['outcome']==('ESTABLISHED' if ok else 'NOT_ESTABLISHED') and d['permitted_operations']==ops,'EVALUATION_REPLAY_MISMATCH')
    need([[r['rule'],r['object'],r['passed']] for r in d['checks']]==checks,'CHECK_TRACE_REPLAY_MISMATCH')
    need(d['components']==components and d['expires_at']==expiry and p['expires_at']==min(expiry,c['valid_until']),'STANDING_OR_EXPIRY_MISMATCH')
    need(d['unknowns']==[{'source_hash':digest(e['payload']),'unknowns':e['payload']['unknowns']} for e in s['nodes']],'UNKNOWNS_MISMATCH')
    need(p['limitations']==d['not_assessed']==p['profile']['not_assessed'] and d['assessment_boundary']==p['profile']['assessed'] and d['review_triggers']==p['profile']['review_triggers'],'ASSESSMENT_CEILING_MISMATCH')
    pid=digest({'domain':'WHP-STANDING-PURCHASE-v1.1','root_pin':pin,'client_reference':s['client_reference']})
    need(pid==p['purchase_id'],'PURCHASE_ID_MISMATCH')
    need(p['mark_id']==('WHP-SM-'+pid if ok else None),'MARK_ID_MISMATCH')
    need(e['protected']['type']==('WHP-STANDING-MARK-v1.1' if ok else 'WHP-STANDING-ASSESSMENT-v1.1'),'INVALID_MARK_PROMOTION')
    need(p['standing']==({'operation':s['requested_operation'],'components':components,'bounds':s['bounds']} if ok else None),'STANDING_BINDING')
    co=p['commerce'];exact(co,['quote','payment_identity','payment_payload','settlement','assessment_paid_by','relationship','assessor']);q=co['quote'];qp=unseal(q,'WHP-STANDING-QUOTE-v1.1',c['public_key'])
    exact(qp,['purchase_id','request_hash','client_reference','profile_hash','issuer','environment','issued_at','expires_at','resource','payment_requirements','charge_policy'])
    need(qp['purchase_id']==pid and qp['request_hash']==digest(s) and qp['client_reference']==s['client_reference'] and qp['profile_hash']==PROFILE_HASH and qp['issuer']==p['issuer'] and qp['environment']==p['environment'],'QUOTE_BINDING')
    pay=co['payment_payload'];a=pay['payload']['authorization'];r=pay['accepted'];settle=co['settlement']
    expected_relationship='Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.' if p['environment']=='TEST' else 'The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.'
    need(co['relationship']==expected_relationship,'PAYMENT_RELATIONSHIP_ENVIRONMENT')
    need(qp['issued_at']<=d['evaluated_at']<qp['expires_at'] and qp['expires_at']>qp['issued_at'],'QUOTE_TIME_BINDING')
    need(int(a['validAfter'])<=d['evaluated_at']<int(a['validBefore']),'PAYMENT_AUTHORIZATION_TIME')
    if p['environment']=='LIVE':
        need(r['network']=='eip155:8453' and r['asset']=='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' and r['payTo']=='0x1050eddd8282623b0c263ed6bdbd42370bbc28d3' and r['extra']['name']=='USD Coin' and r['extra']['version']=='2','LIVE_PAYMENT_DESTINATION')
    need(pay['x402Version']==2 and r==qp['payment_requirements'] and ('resource' not in pay or pay['resource']==qp['resource']),'PAYMENT_TERMS_MISMATCH')
    nonce=a['nonce'].lower()
    need(re.fullmatch(r'0x[0-9a-f]{64}',nonce) is not None and a['to'].lower()==r['payTo'].lower() and a['value']==r['amount'],'PAYMENT_PURCHASE_BINDING')
    identity=digest({'domain':'WHP-EIP3009-PAYMENT-IDENTITY-v1','network':r['network'],'asset':r['asset'].lower(),'authorizer':a['from'].lower(),'nonce':nonce})
    need(co['payment_identity']==identity and co['assessment_paid_by']==a['from'],'PAYMENT_IDENTITY_MISMATCH')
    for name,val in [('environment',p['environment']),('network',r['network']),('asset',r['asset']),('payer',a['from']),('pay_to',a['to']),('amount',a['value']),('nonce',a['nonce'])]: need(settle[name]==val,'SETTLEMENT_BINDING_'+name)
    need(re.fullmatch(r'0x[0-9a-f]{64}',settle['transaction']) is not None,'TRANSACTION_ID_INVALID')
    need(p['retrieval']=={'purchase_path':'/v1/purchases/'+pid,'result_path':'/v1/purchases/'+pid+'/result','registry_path':'/v1/registry/'+pid,'authentication':'Opaque 256-bit purchase capability; no buyer authentication signature','additional_charge':False},'RETRIEVAL_BINDING')
    verify_discovery(p)
    return {'verified':True,'cryptographic_integrity':'VERIFIED','evaluation_replay':'VERIFIED','environment':p['environment'],'purchase_id':pid,'mark_id':p['mark_id'],'assessment':d['outcome'],'current_standing':'NOT_CHECKED','namespace_evidence':'Issuer-signed HTTPS observations replayed; not independent proof of historical GitHub state.','payment_chain_finality':'NOT_RECHECKED' if p['environment']=='LIVE' else 'SIMULATED_NOT_LIVE','expires_at':p['expires_at']}


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
    p=result['payload'];sp=snapshot['payload'];exact(sp,['purchase_id','result_hash','mark_id','status','observed_at','valid_until','events','trust_bundle','authority_evidence']);pa,keys,rev=trust(sp['trust_bundle'],pin,at)
    grant(snapshot,'WHP-REGISTRY-SNAPSHOT-v1','REGISTRY',p['submission']['bounds'],keys,rev,at)
    need(sp['observed_at']<=at+30 and at<sp['valid_until']<=sp['observed_at']+300,'REGISTRY_SNAPSHOT_STALE')
    need(sp['purchase_id']==p['purchase_id'] and sp['result_hash']==bytehash(raw_result) and sp['mark_id']==p['mark_id'],'REGISTRY_RESULT_BINDING')
    need(isinstance(sp['authority_evidence'],list),'NAMESPACE_EVIDENCE_INVALID')
    if sp['authority_evidence']:
        namespace_keys(p['submission'],sp['authority_evidence'],keys,rev,sp['observed_at'])
        need(all(sp['valid_until']<=e['payload']['observed_at']+300 for e in sp['authority_evidence']),'REGISTRY_EVIDENCE_FRESHNESS')
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
            keys=namespace_keys(p['submission'],sp['authority_evidence'],keys,rev,at)
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
