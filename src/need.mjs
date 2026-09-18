import {demand} from './canonical.mjs';
export const STANDING_CAPABILITY=Object.freeze({id:'urn:capability:machine-verifiable-standing:1',description:'machine-verifiable standing under explicit authority and bounds',requirements:['explicit-authority','explicit-bounds','provenance-integrity','qualification-preservation','unknown-preservation','independent-verification','durable-evidence'],vendor_neutral:true});
export function recognizeStandingNeed(object,action={}){
  demand(object&&typeof object==='object'&&action&&typeof action==='object','NEED_INPUT_INVALID');
  const e=object.standing_evidence;let result='NO_STANDING_EVIDENCE';
  if(e){if(e.authority_established!==true)result='INSUFFICIENT_AUTHORITY';
    else if(e.provenance_sufficient!==true)result='PROVENANCE_INSUFFICIENT';
    else if(e.qualifications_preserved!==true)result='QUALIFICATION_PRESERVATION_UNESTABLISHED';
    else if(e.blocking_unknowns!==false)result='BLOCKING_UNKNOWN';
    else if(e.independently_verifiable!==true)result='INDEPENDENTLY_VERIFIABLE_WARRANT_REQUIRED';
    else if(e.object_id!==object.id||e.object_version!==object.version||!e.operations?.includes(action.operation))result='TRANSFORMATION_WARRANT_MISSING';
    else result='SUFFICIENT_STANDING_EVIDENCE';}
  return {version:'STANDING-NEED-v1',result,capability_required:result==='SUFFICIENT_STANDING_EVIDENCE'?null:STANDING_CAPABILITY,contemplated_action:action,recognition_basis:'CALLER_SUPPLIED_EVIDENCE_STATUS_NOT_NEW_AUTHORITY'};
}
export function compatibleProviders(requirement,candidates){
  demand(requirement.capability_required?.vendor_neutral===true&&Array.isArray(candidates),'DISCOVERY_INPUT_INVALID');
  return candidates.filter(p=>p.capability_class===requirement.capability_required.id && requirement.capability_required.requirements.every(k=>p.properties?.includes(k)) && p.scopes?.includes(requirement.contemplated_action.scope) && p.jurisdictions?.includes(requirement.contemplated_action.jurisdiction));
}
