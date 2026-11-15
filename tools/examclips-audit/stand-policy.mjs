import {createPublicKey,createPrivateKey} from 'node:crypto';

export const TARGET='http://127.0.0.1:5173/app/';
export const ORIGIN='http://127.0.0.1:5173';
export function assertLocalTarget(value){
 if(value!==TARGET)throw Error('The test instance target must be the exact approved loopback URL');
 return value;
}
const modelHost=host=>host==='huggingface.co'||host.endsWith('.huggingface.co')||host.endsWith('.hf.co')||
 host==='cdn.jsdelivr.net'||host==='tessdata.projectnaptha.com';
export function requestPolicy(value,method='GET'){
 let url;try{url=new URL(value)}catch{return {allowed:false,reason:'invalid_url'}}
 const safeUrl=url.protocol==='data:'?'data:':url.origin+url.pathname;
 if(url.username||url.password)return {allowed:false,reason:'url_credentials',url:safeUrl};
 if(url.protocol==='data:')return {allowed:true,kind:'inline_data'};
 if(url.protocol==='blob:'){
  try{return {allowed:new URL(url.pathname).origin===ORIGIN,kind:'local_blob'}}catch{return {allowed:false,reason:'foreign_blob'}}
 }
 if(url.origin===ORIGIN){
  if(/^\/(?:auth|billing-api)(?:\/|$)/i.test(url.pathname))return {allowed:false,reason:'auth_or_billing_forbidden',url:safeUrl};
  const allowed=url.pathname==='/site-build.json'||url.pathname==='/healthz'||url.pathname==='/app'||url.pathname.startsWith('/app/')||/^\/api\/local-(?:ocr|review)-capabilities$/.test(url.pathname);
  return {allowed,kind:'test_instance',...(allowed?{}:{reason:'unexpected_local_path'}),url:safeUrl};
 }
 if(url.hostname==='examclips.dpdns.org'||url.hostname.endsWith('.examclips.dpdns.org'))return {allowed:false,reason:'production_origin_forbidden',url:safeUrl};
 if(url.protocol==='https:'&&(!url.port||url.port==='443')&&modelHost(url.hostname))return ['GET','HEAD','OPTIONS'].includes(method)?
  {allowed:true,kind:'public_model',url:safeUrl}:{allowed:false,reason:'public_model_write_forbidden',method,url:safeUrl};
 return {allowed:false,reason:'external_origin_forbidden',url:safeUrl};
}

export function artifactUrl(value){
 let url;try{url=new URL(value)}catch{throw Error('Invalid private artifact origin')}
 const host=url.hostname;
 const allowed=/^(?:sdmntpr|oaisdmntpr|oaisdsorpr)[a-z0-9-]*\.oaiusercontent\.com$/.test(host)||
 /^(?:sdmntpr|oaisdmntpr|oaisdsorpr)[a-z0-9-]*\.blob\.core\.windows\.net$/.test(host);
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.port||!allowed)throw Error('Private artifact origin is not approved');
 if(value.length>16384)throw Error('Private artifact URL is too long');
 return url;
}
export async function fetchArtifact(value,fetcher=fetch){
 let next=artifactUrl(value).href;
 for(let redirects=0;redirects<=4;redirects++){
  const response=await fetcher(next,{redirect:'manual',signal:AbortSignal.timeout(180000)});
  if([301,302,303,307,308].includes(response.status)){
   const location=response.headers.get('location');await response.body?.cancel();
   if(!location)throw Error('Private artifact redirect is missing');
   next=artifactUrl(new URL(location,next).href).href;continue;
  }
  if(response.status!==200)throw Error('Private artifact download returned HTTP '+response.status);
  return response;
 }
 throw Error('Private artifact redirect limit exceeded');
}
export function validatePayload(purpose,payload){
 if(!payload||typeof payload!=='object'||Array.isArray(payload))throw Error('Invalid stand payload');
 const keys=Object.keys(payload).sort().join(',');
 if(purpose==='stand-bundle-prepare'){
  if(keys!=='artifactUrl,bundleRecipientPublicKeyPem'||typeof payload.artifactUrl!=='string'||typeof payload.bundleRecipientPublicKeyPem!=='string')throw Error('Invalid preparation payload shape');
  artifactUrl(payload.artifactUrl);
  if(payload.bundleRecipientPublicKeyPem.length>4096)throw Error('Invalid bundle recipient key');
  let key;try{key=createPublicKey(payload.bundleRecipientPublicKeyPem)}catch{throw Error('Invalid bundle recipient key')}
  if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==4096)throw Error('Bundle recipient must be RSA-4096');
 }else if(purpose==='stand-bundle-unlock'){
  if(keys!=='bundlePrivateKeyPem'||typeof payload.bundlePrivateKeyPem!=='string'||payload.bundlePrivateKeyPem.length>16384)throw Error('Invalid unlock payload shape');
  let key;try{key=createPrivateKey(payload.bundlePrivateKeyPem)}catch{throw Error('Invalid bundle private key')}
  if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==4096)throw Error('Bundle private key must be RSA-4096');
 }else throw Error('Invalid stand handoff purpose');
 return payload;
}
export const publicFailure=()=> 'Stand operation failed; no secret payload or capability URL was logged';

export async function installNetworkPolicy(context,{denied,models}){
 await context.route('**/*',async route=>{
  const decision=requestPolicy(route.request().url(),route.request().method());
  if(!decision.allowed){if(denied.length<1000)denied.push({at:new Date().toISOString(),...decision});return route.abort('blockedbyclient');}
  if(decision.kind==='public_model'&&models.size<2000)models.add(decision.url);
  return route.continue();
 });
}
