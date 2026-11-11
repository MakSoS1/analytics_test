import {gzipSync as compress,gunzipSync as decompress} from 'fflate/browser';
export function gzipSync(bytes){return compress(bytes,{level:6,mtime:0});}
export function gunzipSync(bytes){return decompress(bytes);}
