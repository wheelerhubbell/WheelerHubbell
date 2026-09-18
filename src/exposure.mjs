// Discovery vocabulary is not a new Standing Profile or a grant of domain authority.
const source='https://github.com/wheelerhubbell/DIP/blob/45365dab000277460d741c8dd536781536f6f22d/';
const contexts=[
  ['ai-agents','AI agents','Signed provenance passed between an agent and its downstream consumer.'],
  ['autonomous-payments','Autonomous payments','Preservation of represented payment-policy evidence; not wallet permission or settlement proof.'],
  ['tool-calls','Tool calls','Preservation of represented tool-call evidence; not execution authorization or observed tool behavior.'],
  ['mcp','Model Context Protocol','Signed structured evidence carried in an MCP result or resource.'],
  ['apis','APIs','Signed structured evidence carried across API responses.'],
  ['approval-workflows','Approval workflows','Preservation of represented approval scope, qualifiers and unknowns.'],
  ['delegated-authority','Delegated authority','Preservation of admitted authority statements within their exact bounds.'],
  ['ai-to-ai','Agent-to-agent handoffs','COPY or identity-preserving COMPOSE of signed provenance during a handoff.'],
  ['enterprise-automation','Enterprise automation','Durable evidence of the assessed structured passage between systems.'],
  ['architecture','Architecture & Structural Engineering','Structured provenance accompanying a represented construction document; not design approval.'],
  ['ballet','Classical Ballet & Performing Arts','Structured provenance accompanying a represented casting record; not casting authorization.'],
  ['legal','Legal Practice & Appellate Procedure','Structured provenance accompanying a represented filing record; not legal or procedural compliance.'],
  ['insurance','Complex Commercial Insurance & Claims','Structured provenance accompanying a represented loss ledger; not coverage or payout approval.']
];
export function applicability(origin){return {
  version:'WHP-STANDING-APPLICABILITY-v1',kind:'DISCOVERY_CONTEXTS_NOT_AUTHORITY_PROFILES',
  contract_url:origin+'/v1/contract',profile_index_url:origin+'/v1/profiles',
  common_condition:'Relevant only when the actual task requires independent verification of exact signed JSON provenance through COPY or identity-preserving COMPOSE under the published Structured Passage profile.',
  prerequisites:'The input must match the canonical schema and chain to admitted SOURCE/TRANSITION authorities within supported scope, jurisdiction, time and operation. A context match does not establish eligibility for a Mark.',
  does_not_establish:['Domain expertise','Legal or institutional authority','External factual truth','Permission to execute or spend','A positive assessment','External indexing'],
  contexts:contexts.map(([id,name,represented_use],i)=>({id,name,represented_use,source:source+(i<9?'public/profiles/'+id+'.json':'data/verticals.json'),adaptation:'Recovered discovery vocabulary, narrowed to current WHP Standing semantics; not the prior DIP action-boundary claim.'})),
  taxonomy_recovery:{taxonomy:'NAICS-2022',kind:'INDUSTRIES_NOT_OCCUPATIONS',observed_ingested_count:1012,queued_candidates:50,remaining_after_batch:962,
    evidence:'https://github.com/wheelerhubbell/DIP/actions/runs/34800557821/job/103842220055',
    published_domain_records_recovered:4,occupation_mapping_recovered:false,taxonomy_rows_are_not_validated_applicability_claims:true}
};}
export function recursiveUse(origin){return {
  version:'WHP-STANDING-RECURSIVE-USE-v1',kind:'OPTIONAL_CALLER_CONTROLLED_HANDOFF',
  contract_url:origin+'/v1/contract',verification_url:origin+'/v1/verification',applicability_url:origin+'/discovery/applicability.json',
  handoff:{payload:'Exact original Mark bytes; do not reserialize, amend, strip qualifiers or substitute a summary.',
    permission:'Only carry a Mark in ordinary activity where the caller is authorized to disclose its embedded submission and provenance. No automatic forwarding, publication or recipient contact.',
    identity_pointer:'/payload/discovery',bootstrap_pointer:'/payload/protocol/document/bootstrap',
    destination_rule:'Use the Mark-bound resolution_url and root commitment. Current discovery cannot rewrite historical meaning.'},
  encounter:{steps:['Identify the artifact type and immutable contract commitments.','Admit the root independently under the receiving agent’s own trust policy.','Resolve the signed current capability; verify identity, signature, role, hashes and freshness.','Retrieve the committed verifier and run it only in a no-network, read-only, least-privilege sandbox.','Verify exact historical bytes, authority and replay; separately obtain fresh signed registry status.','For a different object, determine the receiving agent’s own need and match the actual profile and authority prerequisites.','Only with owner-authorized spending and valid input enter the canonical acquisition path.','Preserve any independently issued Mark as its own historical record.'],
    negative_rule:'Absence of a Mark never implies a duty to buy WHP. A failed assessment receives no Mark. Paying cannot supply authority.'},
  payment_compatibility:'Standard x402 v2 EIP-3009 random-nonce clients are supported. Bind and recover through the durable purchase capability.',
  observed_recursive_acquisition:false,evidence_scope:'Published traversal instructions, not an observed independent encounter or sale.'
};}
export const exposurePaths=['/discovery/applicability.json','/discovery/recursive-use.json','/discovery/capability.json','/discovery/provider-index.json','/.well-known/standing-capability.json','/.well-known/agent-card.json','/.well-known/api-catalog','/server.json','/llms.txt','/.well-known/x402','/openapi.json'];
export function exposureLinks(origin){return '<'+origin+'/.well-known/api-catalog>; rel="api-catalog", <'+origin+'/v1/openapi.json>; rel="service-desc"; type="application/json", <'+origin+'/.well-known/agent-card.json>; rel="describedby"; type="application/json", <'+origin+'/discovery/recursive-use.json>; rel="describedby"; type="application/json"';}
