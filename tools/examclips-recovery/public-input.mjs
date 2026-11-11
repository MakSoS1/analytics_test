/**
 * Authenticated GitHub Contents polling for encrypted recovery inputs and small
 * public review commands. No raw.githubusercontent.com branch resolver is used.
 * A 304 is authenticated and does not consume GitHub's primary API allowance.
 */
export function createPublicInputReader({
 repository,branch,prefix,token,fetchImpl=globalThis.fetch,now=Date.now,
 onObservation=()=>{},maxBytes=4*1024**2,missingRetryMs=30000
}){
 if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)||typeof branch!=='string'||!branch||
    !/^\.audit-recovery\/[1-9]\d*\/[1-9]\d*\/(root|ru|en)$/.test(prefix)||!token)
  throw Error('PUBLIC_READER_CONFIGURATION_INVALID');
 const states=new Map();
 const observe=(path,status,start,extra={})=>onObservation({
  transport:'github_contents_api',file:path.slice(prefix.length+1),status,
  elapsedMs:Math.max(0,now()-start),...extra
 });
 function transient(state,path,start,status,headers){
  state.failures=(state.failures||0)+1;
  if(state.failures>12)throw Error('PUBLIC_READ_RETRY_LIMIT');
  const retry=Number(headers?.get('retry-after'));
  const reset=Number(headers?.get('x-ratelimit-reset'));
  const remaining=headers?.get('x-ratelimit-remaining');
  let wait=Math.min(60000,1000*2**Math.min(state.failures,6));
  if(Number.isFinite(retry)&&retry>0)wait=Math.max(wait,retry*1000);
  if(remaining==='0'&&Number.isFinite(reset)&&reset>0)wait=Math.max(wait,reset*1000-now()+1000);
  state.nextRead=now()+Math.min(3600000,Math.max(1000,wait));
  observe(path,status,start,{retryAfterMs:state.nextRead-now(),attempt:state.failures});
  return null;
 }
 async function bodyText(response){
  const declared=response.headers.get('content-length');
  if(declared!==null&&Number(declared)>maxBytes){await response.body?.cancel();throw Error('PUBLIC_INPUT_TOO_LARGE');}
  if(!response.body)throw Error('PUBLIC_INPUT_BODY_MISSING');
  const reader=response.body.getReader(),parts=[];let size=0;
  try{
   while(true){const part=await reader.read();if(part.done)break;
    size+=part.value.byteLength;
    if(size>maxBytes){await reader.cancel();throw Error('PUBLIC_INPUT_TOO_LARGE');}
    parts.push(part.value);
   }
  }finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let offset=0;
  for(const part of parts){bytes.set(part,offset);offset+=part.byteLength;}
  try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
  catch{throw Error('PUBLIC_INPUT_INVALID_UTF8');}
 }
 return async function readPublic(path){
  if(!['fixture.json','input.json','request.json'].some(name=>path===prefix+'/'+name))throw Error('PUBLIC_INPUT_PATH_ESCAPE');
  let state=states.get(path);if(!state){state={nextRead:0,etag:null,text:null,failures:0};states.set(path,state);}
  if(now()<state.nextRead)return null;
  const start=now(),headers={
   Authorization:'Bearer '+token,Accept:'application/vnd.github.raw+json',
   'X-GitHub-Api-Version':'2022-11-28','Cache-Control':'no-cache','Pragma':'no-cache'
  };
  if(state.etag)headers['If-None-Match']=state.etag;
  const url='https://api.github.com/repos/'+repository+'/contents/'+path.split('/').map(encodeURIComponent).join('/')+'?ref='+encodeURIComponent(branch);
  let response;
  try{response=await fetchImpl(url,{headers,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(30000)});}
  catch{return transient(state,path,start,0,null);}
  if(response.status===304){
   if(!state.etag||state.text===null)throw Error('PUBLIC_READ_UNCACHED_304');
   state.failures=0;observe(path,304,start);
   return JSON.parse(state.text);
  }
  if(response.status===404){
   state.text=null;state.etag=null;state.failures=0;state.nextRead=now()+missingRetryMs;
   observe(path,404,start,{retryAfterMs:missingRetryMs});return null;
  }
  const limited=response.status===429||(response.status===403&&(
   response.headers.get('x-ratelimit-remaining')==='0'||response.headers.get('retry-after')!==null));
  if(limited||response.status>=500)return transient(state,path,start,response.status,response.headers);
  if(response.status!==200)throw Error('PUBLIC_READ_HTTP_'+response.status);
  const text=await bodyText(response);let value;
  try{value=JSON.parse(text);}catch{throw Error('PUBLIC_INPUT_INVALID_JSON');}
  state.text=text;state.etag=response.headers.get('etag');state.failures=0;
  state.nextRead=state.etag?0:now()+30000;
  observe(path,200,start,{characters:text.length,etagPresent:!!state.etag,
   remaining:response.headers.get('x-ratelimit-remaining')});
  return value;
 };
}
