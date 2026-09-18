// Small, closed JSON Schema vocabulary used by this contract, with no remote references.
import {canonical,demand} from './canonical.mjs';
export function validateWire(value,schema,path='$') {
  function match(x,s,p){
    if(s.$ref){demand(s.$ref.startsWith('#/$defs/'),'SCHEMA_REMOTE_REF');return match(x,schema.$defs[s.$ref.slice(8)],p);}
    if(Object.hasOwn(s,'const'))demand(canonical(x)===canonical(s.const),'WIRE_CONST',400,p);
    if(s.enum)demand(s.enum.some(v=>canonical(v)===canonical(x)),'WIRE_ENUM',400,p);
    for(const [k,count] of [['oneOf',1],['anyOf',null]])if(s[k]){let n=0;for(const v of s[k])try{match(x,v,p);n++;}catch{}demand(count===null?n>0:n===count,'WIRE_'+k,400,p);}
    if(s.type){const t=x===null?'null':Array.isArray(x)?'array':typeof x==='number'?'integer':typeof x;
      demand(t===s.type && (t!=='integer'||Number.isSafeInteger(x)&&!Object.is(x,-0)),'WIRE_TYPE',400,p);
      if(t==='object'){const ks=Object.keys(x);demand((s.required??[]).every(k=>Object.hasOwn(x,k)),'WIRE_REQUIRED',400,p);
        for(const k of ks){if(s.properties&&Object.hasOwn(s.properties,k))match(x[k],s.properties[k],p+'.'+k);else {demand(s.additionalProperties!==false,'WIRE_UNKNOWN_FIELD',400,p+'.'+k);if(s.additionalProperties&&typeof s.additionalProperties==='object')match(x[k],s.additionalProperties,p+'.'+k);}}}
      if(t==='array'){demand(x.length>=(s.minItems??0)&&x.length<=(s.maxItems??Infinity),'WIRE_ARRAY_LIMIT',400,p);if(s.uniqueItems)demand(new Set(x.map(v=>canonical(v))).size===x.length,'WIRE_DUPLICATE_ITEM',400,p);if(s.items)x.forEach((v,i)=>match(v,s.items,p+'['+i+']'));}
      if(t==='string'){const n=[...x].length;demand(n>=(s.minLength??0)&&n<=(s.maxLength??Infinity),'WIRE_TEXT_LIMIT',400,p);if(s.pattern)demand(new RegExp(s.pattern,'u').test(x),'WIRE_PATTERN',400,p);}
      if(t==='integer')demand(x>=(s.minimum??-Infinity)&&x<=(s.maximum??Infinity),'WIRE_INTEGER_RANGE',400,p);
    }
  }
  canonical(value);match(value,schema,path);return value;
}
