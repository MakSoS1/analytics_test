// Bounded read-only diagnostics. No profile data, browser storage mutation or app instrumentation.
import {appendFile,readFile,stat,statfs} from 'node:fs/promises';
import {dirname,basename,join,resolve} from 'node:path';
import {totalmem,freemem,cpus,loadavg,availableParallelism} from 'node:os';

const safe=value=>String(value??'').replace(/https?:\/\/[^\s"'<>]+/g,value=>{
 try{const url=new URL(value);return url.origin+url.pathname}catch{return '[url]'}
}).replace(/Bearer\s+[A-Za-z0-9._-]+/gi,'Bearer [redacted]')
 .replace(/eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[token]').slice(0,1000);
const errorCode=error=>String(error?.code||error?.name||'Error').slice(0,80);
const integer=value=>Number.isSafeInteger(Number(value))?Number(value):String(value);
const finite=value=>typeof value==='number'&&Number.isFinite(value)?value:null;

export const isMaterialBlobFailure=(url,errorText)=>String(url).startsWith('blob:')&&!!errorText&&!/ERR_ABORTED|ABORT_ERR/i.test(String(errorText));

async function filesystemObservation({role,path}){
 let probe=resolve(path),ancestorLevels=0;
 while(true){
  try{
   const [capacity,identity]=await Promise.all([statfs(probe,{bigint:true}),stat(probe,{bigint:true})]);
   return {role,status:'ok',requestedPathExists:ancestorLevels===0,ancestorLevels,
    device:identity.dev.toString(),filesystemType:capacity.type.toString(),
    blockSizeBytes:integer(capacity.bsize),blocks:integer(capacity.blocks),blocksFree:integer(capacity.bfree),
    blocksAvailable:integer(capacity.bavail),files:integer(capacity.files),filesFree:integer(capacity.ffree),
    freeBytes:integer(capacity.bsize*capacity.bfree),availableBytes:integer(capacity.bsize*capacity.bavail)};
  }catch(error){
   if(!['ENOENT','ENOTDIR'].includes(error.code)||dirname(probe)===probe)return {role,status:'error',error:errorCode(error),ancestorLevels};
   probe=dirname(probe);ancestorLevels++;
  }
 }
}

async function hostMemoryObservation(){
 const result={totalBytes:totalmem(),freeBytes:freemem(),memAvailableBytes:null,memAvailableStatus:'unavailable',
  cgroup:{status:'unavailable',currentBytes:null,maxBytes:null,unlimited:null,events:null}};
 try{
  const text=await readFile('/proc/meminfo','utf8'),match=text.match(/^MemAvailable:\s+(\d+)\s+kB$/m);
  if(match){result.memAvailableBytes=Number(match[1])*1024;result.memAvailableStatus='ok'}
 }catch(error){result.memAvailableError=errorCode(error)}
 try{
  const membership=await readFile('/proc/self/cgroup','utf8'),match=membership.match(/^0::(\/[^\n]*)$/m);
  if(!match)return result;
  const base=resolve('/sys/fs/cgroup','.'+match[1]);
  if(base!=='/sys/fs/cgroup'&&!base.startsWith('/sys/fs/cgroup/'))return result;
  const values=await Promise.allSettled(['memory.current','memory.max','memory.events'].map(name=>readFile(join(base,name),'utf8')));
  result.cgroup.status=values.every(value=>value.status==='fulfilled')?'ok':'partial';
  const current=values[0].status==='fulfilled'?values[0].value.trim():null;
  const maximum=values[1].status==='fulfilled'?values[1].value.trim():null;
  if(current&&/^\d+$/.test(current))result.cgroup.currentBytes=integer(current);
  if(maximum==='max')result.cgroup.unlimited=true;
  else if(maximum&&/^\d+$/.test(maximum)){result.cgroup.maxBytes=integer(maximum);result.cgroup.unlimited=false}
  if(values[2].status==='fulfilled')result.cgroup.events=Object.fromEntries(values[2].value.trim().split('\n').map(row=>row.trim().split(/\s+/)).filter(([name,value])=>/^[a-z_]+$/.test(name)&&/^\d+$/.test(value)).map(([name,value])=>[name,integer(value)]));
  result.cgroup.errors=values.map((value,index)=>value.status==='rejected'?{field:['current','max','events'][index],error:errorCode(value.reason)}:null).filter(Boolean);
 }catch(error){result.cgroup.error=errorCode(error)}
 return result;
}

function hostCpuObservation(){
 const processors=cpus(),cumulativeTimesMs={user:0,nice:0,sys:0,idle:0,irq:0};
 for(const processor of processors)for(const key of Object.keys(cumulativeTimesMs))cumulativeTimesMs[key]+=processor.times[key]||0;
 return {logicalCpuCount:processors.length,availableParallelism:availableParallelism(),model:processors[0]?.model||null,
  loadAverage:loadavg(),cumulativeTimesMs,
  interpretation:'Host CPU counters and load averages, not browser-process CPU or a one-snapshot utilization percentage.'};
}

// Serialized by Playwright; keep this function independent of module closure values.
export async function readPageResources(){
 const numeric=value=>typeof value==='number'&&Number.isFinite(value)?value:null;
 const heap=performance.memory;
 const row={status:'ok',origin:location.origin,
  mainPageJsHeap:{status:heap?'available':'unavailable',usedBytes:numeric(heap?.usedJSHeapSize),totalBytes:numeric(heap?.totalJSHeapSize),limitBytes:numeric(heap?.jsHeapSizeLimit)},
  originStorage:{estimateStatus:'unsupported',persistedStatus:'unsupported',usageBytes:null,quotaBytes:null,usageDetails:null,persisted:null}};
 const storage=navigator.storage;
 await Promise.all([
  (async()=>{if(typeof storage?.estimate!=='function')return;
   try{const estimate=await storage.estimate();row.originStorage.estimateStatus='ok';row.originStorage.usageBytes=numeric(estimate.usage);row.originStorage.quotaBytes=numeric(estimate.quota);
    if(estimate.usageDetails&&typeof estimate.usageDetails==='object')row.originStorage.usageDetails=Object.fromEntries(Object.entries(estimate.usageDetails).slice(0,20).filter(([name,value])=>/^[a-zA-Z0-9_-]{1,60}$/.test(name)&&numeric(value)!==null));
   }catch(error){row.originStorage.estimateStatus='error';row.originStorage.estimateError=String(error?.name||'Error').slice(0,80)}
  })(),
  (async()=>{if(typeof storage?.persisted!=='function')return;
   try{const persisted=await storage.persisted();row.originStorage.persistedStatus='ok';row.originStorage.persisted=typeof persisted==='boolean'?persisted:null}
   catch(error){row.originStorage.persistedStatus='error';row.originStorage.persistedError=String(error?.name||'Error').slice(0,80)}
  })()
 ]);
 return row;
}

function deadline(operation,milliseconds){
 return new Promise(resolvePromise=>{
  const timer=setTimeout(()=>resolvePromise({status:'timeout'}),milliseconds);
  Promise.resolve(operation).then(value=>{clearTimeout(timer);resolvePromise(value)},error=>{clearTimeout(timer);resolvePromise({status:'error',error:errorCode(error)})});
 });
}

export function createResourceObserver({file,paths,maxSamples=18,pageTimeoutMs=2500}){
 if(!Number.isInteger(maxSamples)||maxSamples<1||maxSamples>30)throw Error('Invalid diagnostic sample cap');
 if(!Number.isFinite(pageTimeoutMs)||pageTimeoutMs<1||pageTimeoutMs>5000)throw Error('Invalid diagnostic page deadline');
 let pending=Promise.resolve(),requested=0,written=0,capped=0,writeFailures=0;
 const observe=(label,{page,metadata={}}={})=>{
  if(requested>=maxSamples){capped++;return Promise.resolve(null)}
  const sequence=++requested,observedAt=new Date().toISOString();
  const selected={};
  for(const key of ['phase','asrSourceSeconds','sourceBytes','sourceSha256','sourceDurationSeconds','eventType','errorText','blobUrl']){
   if(metadata[key]===undefined)continue;
   selected[key]=typeof metadata[key]==='number'?finite(metadata[key]):safe(metadata[key]);
  }
  pending=pending.catch(()=>{}).then(async()=>{
   const [filesystems,hostMemory,pageState]=await Promise.all([
    Promise.all(paths.map(filesystemObservation)),hostMemoryObservation(),
    page?deadline(Promise.resolve().then(()=>page.evaluate(readPageResources)),pageTimeoutMs):Promise.resolve({status:'not_requested'})
   ]);
   const row={schema:1,sequence,observedAt,collectedAt:new Date().toISOString(),label:safe(label),metadata:selected,
    filesystems,hostMemory,hostCpu:hostCpuObservation(),page:pageState,
    interpretation:'Host/cgroup memory, main-page JS heap and origin storage quota are separate observations. None measures browser Blob capacity, worker/WASM memory or establishes a cause.'};
   try{await appendFile(file,JSON.stringify(row)+'\n',{mode:0o600});written++;return row}catch{writeFailures++;return null}
  }).catch(()=>{writeFailures++;return null});
  return pending;
 };
 return {observe,flush:(milliseconds=4000)=>deadline(pending,milliseconds),
  summary:()=>({file:basename(file),requested,written,capped,writeFailures,maxSamples,pageTimeoutMs,
   readOnly:true,profileContentsCollected:false,storageMutated:false})};
}
