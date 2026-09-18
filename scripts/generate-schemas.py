"""Build inspectable schemas from the frozen v1 wire contract, not runtime inference."""
import json, hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROFILE=json.loads((ROOT/'profiles/structured-passage-1.1.0.json').read_text())
H=hashlib.sha256(json.dumps(PROFILE,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
def ref(n):return {'$ref':'#/$defs/'+n}
def obj(p,required=None):return {'type':'object','properties':p,'required':list(p) if required is None else required,'additionalProperties':False}
def arr(x,max=128,min=0,unique=False):return {'type':'array','items':x,'minItems':min,'maxItems':max,**({'uniqueItems':True} if unique else {})}
def enum(*x):return {'enum':list(x)}
def const(x):return {'const':x}
S={'type':'string','minLength':1,'maxLength':4096}
I={'type':'integer','minimum':0,'maximum':9007199254740991}
HASH={'type':'string','pattern':'^[0-9a-f]{64}$'}
HEX={'type':'string','pattern':'^0x[0-9a-fA-F]{64}$'}
ADDR={'type':'string','pattern':'^0x[0-9a-fA-F]{40}$'}
NUM={'type':'string','pattern':'^(0|[1-9][0-9]{0,77})$','x-whp-uint256':True}
OPS=enum('INFORM','RECOMMEND','EXECUTE')
OPLIST=arr(OPS,3,unique=True)
PUB={'type':'string','maxLength':256,'description':'Canonical base64 DER SubjectPublicKeyInfo containing exactly an Ed25519 public key.'}
BOUNDS=obj({'scope':S,'jurisdiction':S,'valid_from':I,'valid_until':I})
OBJECT=obj({'id':S,'version':S,'root':HASH})
SIG={'type':'string','pattern':'^[A-Za-z0-9+/]{86}==$'}
def envelope(kind,payload):return obj({'protected':obj({'type':const(kind),'algorithm':const('Ed25519'),'canonicalization':const('WHP-JCS-I1'),'key_id':HASH}),'payload':payload,'signature':SIG})
D={'hash':HASH,'bounds':BOUNDS,'object':OBJECT,'public_key':PUB,'operation':OPS}
D['value']={'oneOf':[{'type':'null'},{'type':'boolean'},{'type':'integer','minimum':-9007199254740991,'maximum':9007199254740991},{'type':'string'},{'type':'array','items':ref('value')},{'type':'object','additionalProperties':ref('value')}],'description':'WHP-JCS-I1 additionally forbids lone surrogates, negative zero, duplicate object keys and excessive nesting.'}
D['unknown']=obj({'id':S,'description':S,'blocks':OPLIST})
unknowns=arr(ref('unknown'),64,unique=True);unknowns['x-whp-unique-key']='id'
D['node_payload']=obj({'id':S,'version':S,'content':ref('value'),'locator':S,'epistemic_status':enum('OBSERVATION','REPORT','FINDING','INFERENCE','HYPOTHESIS','UNKNOWN'),'qualifiers':arr(S,128,unique=True),'unknowns':unknowns,'operations':OPLIST,'scope':S,'jurisdiction':S,'valid_from':I,'valid_until':I,'status':enum('ACTIVE','CORRECTED','SUPERSEDED','DISPUTED','WITHDRAWN'),'prior_hash':{'anyOf':[HASH,{'type':'null'}]}})
D['source']=envelope('WHP-SOURCE-ATTESTATION-v1',ref('node_payload'))
D['transition_payload']=obj({'from':arr(HASH,64,1,True),'to':HASH,'transform':enum('COPY','COMPOSE'),'operations':OPLIST,'scope':S,'jurisdiction':S,'valid_from':I,'valid_until':I,'warrant':obj({'statement':S,'evidence_hashes':arr(HASH,64,unique=True)})})
D['transition']=envelope('WHP-TRANSITION-WARRANT-v1',ref('transition_payload'))
D['namespace_request']=obj({'namespace':{'type':'string','pattern':r'^https://github\.com/[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_][a-z0-9_.-]{0,99}$'},'manifest_sha256':HASH})
D['namespace_observation']=envelope('WHP-NAMESPACE-OBSERVATION-v1',obj({'version':const('WHP-NAMESPACE-OBSERVATION-v1'),'namespace':S,'manifest_raw':{'type':'string','maxLength':32768},'manifest_sha256':HASH,'blob_sha':{'type':'string','pattern':'^[0-9a-f]{40}$'},'observed_at':I}))
D['profile_ref']=const({'id':PROFILE['id'],'version':PROFILE['version'],'sha256':H})
D['submission']=obj({'version':const('WHP-STANDING-SUBMISSION-v1.1'),'client_reference':HASH,'authority':arr(ref('namespace_request'),8),'profile':ref('profile_ref'),'object':OBJECT,'bounds':BOUNDS,'requested_operation':OPS,'nodes':arr(ref('source'),64,1),'transitions':arr(ref('transition'),64)})
D['profile_authorization']=envelope('WHP-PROFILE-AUTHORIZATION-v1',obj({'profile_hash':const(H),'contract_hash':HASH,'verifier_sha256':HASH,'ratified':const(True),'issuer':S,'environment':enum('TEST','LIVE'),'valid_from':I,'valid_until':I}))
D['certificate']=envelope('WHP-AUTHORITY-CERTIFICATE-v1',obj({'public_key':PUB,'subject':S,'roles':arr(enum('SOURCE','TRANSITION','ISSUER','REGISTRY','DISCOVERY'),64),'scopes':arr(S,64),'jurisdictions':arr(S,64),'operations':OPLIST,'profile_hash':const(H),'valid_from':I,'valid_until':I}))
D['revocation']=envelope('WHP-KEY-REVOCATION-v1',obj({'key_id':HASH,'effective_at':I,'reason':S}))
D['trust_status']=envelope('WHP-TRUST-STATUS-v1',obj({'sequence':I,'previous_hash':{'anyOf':[HASH,{'type':'null'}]},'profile_authorization_hash':HASH,'certificates_hash':HASH,'revocations_hash':HASH,'valid_from':I,'valid_until':I}))
D['trust_bundle']=obj({'root_public_key':PUB,'profile_authorization':ref('profile_authorization'),'certificates':arr(ref('certificate'),128),'revocations':arr(ref('revocation'),128),'status_snapshot':ref('trust_status')})
D['requirements']=obj({'scheme':const('exact'),'network':{'type':'string','pattern':'^eip155:[1-9][0-9]*$'},'amount':NUM,'asset':ADDR,'payTo':ADDR,'maxTimeoutSeconds':{'type':'integer','minimum':1,'maximum':300},'extra':obj({'assetTransferMethod':const('eip3009'),'paymentFlow':const('authorization'),'name':S,'version':S})})
D['resource']=obj({'url':S,'description':S,'mimeType':const('application/json')})
D['quote']=envelope('WHP-STANDING-QUOTE-v1.1',obj({'purchase_id':HASH,'request_hash':HASH,'client_reference':HASH,'profile_hash':const(H),'issuer':S,'environment':enum('TEST','LIVE'),'issued_at':I,'expires_at':I,'resource':ref('resource'),'payment_requirements':ref('requirements'),'charge_policy':S}))
D['payment']=obj({'x402Version':const(2),'resource':ref('resource'),'accepted':ref('requirements'),'payload':obj({'signature':{'type':'string','pattern':'^0x[0-9a-fA-F]{128}(00|01|1[bBcC])$'},'authorization':obj({'from':ADDR,'to':ADDR,'value':NUM,'validAfter':NUM,'validBefore':NUM,'nonce':HEX})})})
D['payment']['properties']['extensions']=ref('value')
D['payment']['required']=['x402Version','accepted','payload']
D['components']=obj({k:enum('ESTABLISHED','NOT_ESTABLISHED','NOT_ASSESSED') for k in ['SOURCE','CONTEXT','RELATION','PASSAGE','UNKNOWN','CONTINUITY','ACTION_BOUNDARY']})
D['check']={'oneOf':[obj({'rule':const(k),'object':HASH,'passed':{'type':'boolean'},'detail':const(v)}) for k,v in json.loads((ROOT/'contracts/check-details.json').read_text()).items()]}
D['decision']=obj({'version':const('WHP-STANDING-DECISION-v1.1'),'evaluated_at':I,'submission_hash':HASH,'object':OBJECT,'profile':ref('profile_ref'),'bounds':BOUNDS,'requested_operation':OPS,'outcome':enum('ESTABLISHED','NOT_ESTABLISHED'),'permitted_operations':OPLIST,'components':ref('components'),'effective_at':I,'expires_at':I,'checks':arr(ref('check'),1024),'unknowns':arr(obj({'source_hash':HASH,'unknowns':unknowns}),64),'assessment_boundary':const(PROFILE['assessed']),'not_assessed':const(PROFILE['not_assessed']),'review_triggers':const(PROFILE['review_triggers'])})
common={'version':S,'environment':enum('TEST','LIVE'),'network':S,'asset':ADDR,'payer':ADDR,'pay_to':ADDR,'amount':NUM,'nonce':HEX,'transaction':HEX,'block_number':I,'block_hash':HEX,'finality':S,'observed_at':I,'verification_boundary':S}
D['settlement_test']=obj({**common,'version':const('WHP-TEST-SETTLEMENT-EVIDENCE-v1'),'environment':const('TEST'),'finality':const('SIMULATED_NOT_LIVE')})
D['settlement_live']=obj({**common,'version':const('WHP-EIP3009-SETTLEMENT-EVIDENCE-v1'),'environment':const('LIVE'),'finality':const('finalized'),'finalized_head':obj({'number':S,'hash':HEX}),'authorization_log':ref('value'),'transfer_log':ref('value'),'transaction_input':S})
D['commerce']=obj({'quote':ref('quote'),'payment_identity':HASH,'payment_payload':ref('payment'),'settlement':{'oneOf':[ref('settlement_test'),ref('settlement_live')]},'assessment_paid_by':ADDR,'relationship':enum('Simulated buyer and test issuer only. No Wheeler Hubbell Publishing sale or real funds transfer occurred.','The buyer pays Wheeler Hubbell Publishing for assessment. Payment does not determine the assessment outcome.'),'assessor':const('WHP Standing deterministic Structured Passage evaluator 1.1.0')})
D['result_payload']=obj({'version':const('WHP-STANDING-RESULT-v1.1'),'environment':enum('TEST','LIVE'),'issuer':S,'issuer_key_id':HASH,'purchase_id':HASH,'mark_id':{'anyOf':[{'type':'string','pattern':'^WHP-SM-[0-9a-f]{64}$'},{'type':'null'}]},'issued_at':I,'effective_at':I,'expires_at':I,'object':OBJECT,'profile':const(PROFILE),'profile_authorization':ref('profile_authorization'),'authority':ref('trust_bundle'),'authority_evidence':arr(ref('namespace_observation'),8),'submission':ref('submission'),'submission_hash':HASH,'decision_record':ref('decision'),'decision_record_ref':{'type':'string','pattern':'^urn:sha256:[0-9a-f]{64}$'},'standing':{'anyOf':[{'type':'null'},obj({'operation':OPS,'components':ref('components'),'bounds':BOUNDS})]},'commerce':ref('commerce'),'retrieval':obj({'purchase_path':S,'result_path':S,'registry_path':S,'authentication':S,'additional_charge':const(False)}),'limitations':const(PROFILE['not_assessed']),'current_status_rule':S})
MANIFEST=json.loads((ROOT/'contracts/manifest-template.json').read_text())
D['contract_document']=obj({**{k:const(v) for k,v in MANIFEST.items()},'schema_sha256':HASH})
D['protocol']=obj({'document':ref('contract_document'),'sha256':HASH,'verifier_sha256':HASH})
D['discovery_identity']=obj({'version':const('WHP-STANDING-DISCOVERY-IDENTITY-v1'),'capability_id':const('urn:whp:standing:capability:1'),'capability_class':const('urn:capability:machine-verifiable-standing:1'),'resolution_id':const('urn:whp:standing:resolution:1'),'resolution_url':S,'root_key_id':HASH,'status_id':{'type':'string','pattern':'^urn:whp:standing:status:[0-9a-f]{64}$'}})
D['result_payload']['properties']['discovery']=ref('discovery_identity')
D['result_payload']['properties']['protocol']=ref('protocol')
D['result_payload']['required']+=['discovery','protocol']
D['result_payload']['properties']['current_status_rule']=const('This immutable record proves issuance-time assessment. Current standing requires a fresh signed registry response and current trust/revocation information.')
D['artifact_location']=obj({'kind':enum('PROFILE','CONTRACT','SCHEMA','VERIFIER'),'id':S,'version':S,'sha256':HASH,'url':S,'media_type':S})
D['resolution_payload']=obj({'version':const('WHP-CAPABILITY-RESOLUTION-v1'),'capability_id':const('urn:whp:standing:capability:1'),'capability_class':const('urn:capability:machine-verifiable-standing:1'),'resolution_id':const('urn:whp:standing:resolution:1'),'issuer':S,'environment':enum('TEST','LIVE'),'root_key_id':HASH,'observed_at':I,'valid_until':I,'trust_bundle':ref('trust_bundle'),'authority_context':obj({'scope':S,'jurisdiction':S}),'service_origin':S,'service_contract':obj({'url':S,'sha256':HASH}),'openapi':obj({'url':S,'sha256':HASH}),'artifacts':arr(ref('artifact_location'),16,4),'registry_template':S,'provider_discovery':obj({'interface':const('capability-catalog-v1'),'url':{'anyOf':[S,{'type':'null'}]}}),'availability':enum('TEST_ONLY','CONFIGURED_LIVE_NOT_SALE_PROVEN')})
D['resolution']=envelope('WHP-CAPABILITY-RESOLUTION-v1',ref('resolution_payload'))
D['mark']=envelope('WHP-STANDING-MARK-v1.1',ref('result_payload'))
D['assessment']=envelope('WHP-STANDING-ASSESSMENT-v1.1',ref('result_payload'))
def document(name,body):return {'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:whp:standing:v1.1:'+name,'title':'WHP Standing v1.1 '+name,'$defs':D,**body,'x-whp-canonicalization':'WHP-JCS-I1','x-whp-cross-field-constraints':'See docs/FIRST-PUBLIC-V1.md; signatures, dates, graph closure, binding, authority and issuance conditions require semantic verification.'}
for name,body in {'submission':ref('submission'),'result':{'oneOf':[ref('mark'),ref('assessment')]},'trust-bundle':ref('trust_bundle'),'payment-requirements':ref('requirements'),'discovery-resolution':ref('resolution')}.items():
    # Each file is self-contained so agents need no hidden remote schema fetches.
    doc=document(name,body)
    needed=set()
    def collect(x):
        if isinstance(x,dict):
            if '$ref' in x:
                n=x['$ref'].split('/')[-1]
                if n not in needed:needed.add(n);collect(D[n])
            for k,v in x.items():
                if k!='$defs':collect(v)
        elif isinstance(x,list):
            for v in x:collect(v)
    collect(body);doc['$defs']={k:v for k,v in D.items() if k in needed}
    (ROOT/'schemas'/f'{name}.schema.json').write_text(json.dumps(doc,indent=2,ensure_ascii=False)+'\n')
