import { createHash, createPublicKey, createPrivateKey, sign, verify, randomBytes } from 'node:crypto';

export class Fault extends Error {
  constructor(code, status = 400, path = '$') { super(code); this.code = code; this.status = status; this.path = path; }
}
export const demand = (ok, code, status = 400, path = '$') => { if (!ok) throw new Fault(code, status, path); };
export const clone = x => JSON.parse(JSON.stringify(x));

// WHP JCS-I1: RFC 8785 on a deliberately restricted I-JSON subset.
// Only safe integers are admitted; decimal quantities are strings. No Unicode normalization.
export function canonical(x, depth = 0) {
  demand(depth <= 64, 'JSON_DEPTH');
  if (x === null) return 'null';
  if (typeof x === 'boolean') return x ? 'true' : 'false';
  if (typeof x === 'number') { demand(Number.isSafeInteger(x) && !Object.is(x, -0), 'INTEGER_REQUIRED'); return String(x); }
  if (typeof x === 'string') { demand(x.isWellFormed(), 'INVALID_UNICODE'); return JSON.stringify(x); }
  if (Array.isArray(x)) {
    demand(Reflect.ownKeys(x).length===x.length+1 && Array.from({length:x.length},(_,i)=>Object.getOwnPropertyDescriptor(x,String(i))).every(d=>d && 'value' in d && d.enumerable),'JSON_ARRAY_PROPERTIES');
    return '[' + x.map(v => canonical(v, depth + 1)).join(',') + ']';
  }
  demand(x && typeof x === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(x)), 'JSON_OBJECT_REQUIRED');
  demand(Reflect.ownKeys(x).every(k=>typeof k==='string' && Object.getOwnPropertyDescriptor(x,k).enumerable && 'value' in Object.getOwnPropertyDescriptor(x,k)),'JSON_OBJECT_PROPERTIES');
  return '{' + Object.keys(x).sort().map(k => canonical(k, depth + 1) + ':' + canonical(x[k], depth + 1)).join(',') + '}';
}
// A parser, not JSON.parse with a reviver: duplicate keys must be rejected before loss.
export function parseStrict(text, maxBytes = 262144) {
  demand(typeof text === 'string' && Buffer.byteLength(text) <= maxBytes, 'BODY_TOO_LARGE', 413);
  let i = 0;
  function ws() { while (/[\x20\t\r\n]/.test(text[i] ?? '\0')) i++; }
  function str() {
    demand(text[i] === '"', 'INVALID_JSON'); let start = i++;
    while (i < text.length) { const c = text[i++]; if (c === '\\') i++; else if (c === '"') {
      let s; try { s = JSON.parse(text.slice(start, i)); } catch { throw new Fault('INVALID_JSON'); }
      demand(s.isWellFormed(), 'INVALID_UNICODE'); return s;
    }} throw new Fault('INVALID_JSON');
  }
  function val(d) {
    demand(d <= 64, 'JSON_DEPTH'); ws(); const c = text[i];
    if (c === '"') return str();
    if (c === '{') { i++; ws(); const o = Object.create(null), seen = new Set();
      if (text[i] === '}') { i++; return o; }
      for (;;) { ws(); const k = str(); demand(!seen.has(k), 'DUPLICATE_JSON_KEY'); seen.add(k);
        ws(); demand(text[i++] === ':', 'INVALID_JSON'); o[k] = val(d + 1); ws();
        const sep = text[i++]; if (sep === '}') return o; demand(sep === ',', 'INVALID_JSON'); }
    }
    if (c === '[') { i++; ws(); const a = []; if (text[i] === ']') { i++; return a; }
      for (;;) { a.push(val(d + 1)); ws(); const sep = text[i++]; if (sep === ']') return a; demand(sep === ',', 'INVALID_JSON'); }
    }
    for (const [s, v] of [['true', true], ['false', false], ['null', null]]) if (text.startsWith(s, i)) { i += s.length; return v; }
    const m = text.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    demand(m, 'INVALID_JSON'); demand(!/[.eE]/.test(m[0]) && m[0] !== '-0', 'INTEGER_TOKEN_REQUIRED'); i += m[0].length; const n = Number(m[0]); canonical(n); return n;
  }
  const out = val(0); ws(); demand(i === text.length, 'INVALID_JSON'); canonical(out); return out;
}
export const hashBytes = x => createHash('sha256').update(x).digest('hex');
export const hash = x => hashBytes(Buffer.from(canonical(x)));
export const randomHex = (n = 32) => randomBytes(n).toString('hex');
export const encode = x => Buffer.from(canonical(x)).toString('base64');
export function decode(s, max = 65536) {
  demand(typeof s === 'string' && s.length <= max && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s), 'INVALID_BASE64');
  const bytes = Buffer.from(s, 'base64');demand(bytes.toString('base64')===s,'NONCANONICAL_BASE64');let text;
  try{text=new TextDecoder('utf-8', {fatal:true}).decode(bytes);}catch{throw new Fault('INVALID_UTF8');}
  return parseStrict(text, max);
}
export function publicDer(key) { return createPublicKey(key).export({type:'spki', format:'der'}).toString('base64'); }
export function keyObject(der) {
  demand(typeof der === 'string' && der.length < 256, 'INVALID_PUBLIC_KEY');
  let k; try { k = createPublicKey({key:Buffer.from(der, 'base64'), type:'spki', format:'der'}); } catch { throw new Fault('INVALID_PUBLIC_KEY'); }
  demand(k.asymmetricKeyType === 'ed25519' && k.export({type:'spki',format:'der'}).toString('base64') === der, 'INVALID_PUBLIC_KEY'); return k;
}
export const keyId = der => hashBytes(Buffer.from(der, 'base64'));
export function seal(type, payload, privateKey) {
  const pub = publicDer(privateKey);
  const unsigned = {protected:{type, algorithm:'Ed25519', canonicalization:'WHP-JCS-I1', key_id:keyId(pub)}, payload};
  return {...unsigned, signature:sign(null, Buffer.from(canonical(unsigned)), privateKey).toString('base64')};
}
export function openSeal(envelope, type, pub) {
  exact(envelope, ['protected','payload','signature']);
  exact(envelope.protected, ['type','algorithm','canonicalization','key_id']);
  demand(envelope.protected.type === type && envelope.protected.algorithm === 'Ed25519' && envelope.protected.canonicalization === 'WHP-JCS-I1' && envelope.protected.key_id === keyId(pub), 'SIGNATURE_CONTEXT');
  demand(typeof envelope.signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(envelope.signature), 'INVALID_SIGNATURE');
  demand(Buffer.from(envelope.signature,'base64').toString('base64')===envelope.signature,'NONCANONICAL_SIGNATURE');
  const u = {protected:envelope.protected,payload:envelope.payload};
  demand(verify(null, Buffer.from(canonical(u)), keyObject(pub), Buffer.from(envelope.signature, 'base64')), 'INVALID_SIGNATURE');
  return envelope.payload;
}
export function exact(o, fields, path = '$') {
  demand(o && !Array.isArray(o) && typeof o === 'object', 'OBJECT_REQUIRED', 400, path);
  demand(Object.keys(o).length === fields.length && fields.every(k=>Object.hasOwn(o,k)), 'FIELDS_INVALID', 400, path);
}
export function text(s, path = '$', max = 4096) { demand(typeof s === 'string' && s.length > 0 && s.length <= max && s.isWellFormed(), 'TEXT_REQUIRED', 400, path); }
export function array(a, max = 128, path = '$') { demand(Array.isArray(a) && a.length <= max, 'ARRAY_INVALID', 400, path); }
export function unique(a, path = '$') { demand(new Set(a.map(x=>canonical(x))).size === a.length, 'DUPLICATE_ITEM', 400, path); }
export function timeWindow(o, path = '$') { demand(Number.isSafeInteger(o.valid_from) && Number.isSafeInteger(o.valid_until) && o.valid_from >= 0 && o.valid_until > o.valid_from, 'INVALID_TIME_WINDOW', 400, path); }
