import value from '../profiles/structured-passage-1.1.0.json' with {type:'json'};
import { hash, clone } from './canonical.mjs';
export const PROFILE_HASH = hash(value);
export const profile = () => clone(value);
export const PROFILE_ID = value.id;
export const OPERATIONS = value.operations;
export const PROFILE_VERSION = value.version;
