import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const api=()=>import('./resource-observation.mjs');

test('ordinary aborted Blob fetches do not consume the later material-failure sample budget',async()=>{
 const {isMaterialBlobFailure}=await api();
 const before=Array.from({length:8},()=>({url:'blob:http://127.0.0.1:5173/upload-id',error:'net::ERR_ABORTED'}));
 const failed={url:'blob:http://127.0.0.1:5173/model-id',error:'net::ERR_BLOB_OUT_OF_MEMORY'};
 const material=[...before,failed].filter(row=>isMaterialBlobFailure(row.url,row.error));
 assert.deepEqual(material,[failed]);
 assert.equal(isMaterialBlobFailure('https://example.com/model','net::ERR_FAILED'),false);
 assert.equal(isMaterialBlobFailure(failed.url,'net::ERR_FILE_NOT_FOUND'),true);
});

test('read-only host observation records real filesystem capacity without collecting profile contents',async()=>{
 const {createResourceObserver}=await api();
 const root=await mkdtemp(join(tmpdir(),'audit-observer-'));
 try{
  const profile=join(root,'profile');await mkdir(profile);await writeFile(join(profile,'private-cookie'),'private-content-not-evidence');
  const evidence=join(root,'evidence');await mkdir(evidence);
  const file=join(evidence,'resources.jsonl');
  const observer=createResourceObserver({file,paths:[{role:'profile',path:profile},{role:'future_source',path:join(root,'not-created','media')}]});
  await observer.observe('before_browser');await observer.flush();
  const raw=await readFile(file,'utf8'),row=JSON.parse(raw);
  assert.equal(row.filesystems[0].status,'ok');
  assert.ok(Number(row.filesystems[0].availableBytes)>0);
  assert.ok(Number(row.filesystems[0].blockSizeBytes)>0);
  assert.equal(row.filesystems[0].ancestorLevels,0);
  assert.equal(row.filesystems[1].ancestorLevels,2);
  assert.equal(row.filesystems[1].requestedPathExists,false);
  assert.equal(row.hostMemory.totalBytes>0,true);
  assert.ok(row.hostCpu.logicalCpuCount>0);assert.equal(row.hostCpu.loadAverage.length,3);
  assert.ok(row.hostCpu.cumulativeTimesMs.idle>=0);
  assert.equal(row.page.status,'not_requested');
  assert.equal(raw.includes(root),false);assert.equal(raw.includes('private-cookie'),false);assert.equal(raw.includes('private-content'),false);
  assert.deepEqual(await readdir(profile),['private-cookie']);
  assert.equal(await readFile(join(profile,'private-cookie'),'utf8'),'private-content-not-evidence');
  assert.equal(observer.summary().written,1);
 }finally{await rm(root,{recursive:true,force:true})}
});

test('a stuck or failed browser observation stays bounded and does not stop later evidence',async()=>{
 const {createResourceObserver}=await api();const root=await mkdtemp(join(tmpdir(),'audit-observer-'));
 try{
  const file=join(root,'resources.jsonl');
  const observer=createResourceObserver({file,paths:[],pageTimeoutMs:30,maxSamples:3});
  const started=Date.now();
  await observer.observe('model_prepare',{page:{evaluate:()=>new Promise(()=>{})}});
  await observer.observe('request_failed',{page:{evaluate:()=>Promise.reject(Error('private path or secret'))}});
  await observer.observe('after_failure');
  await observer.observe('over_cap');await observer.flush();
  assert.ok(Date.now()-started<2000);
  const raw=await readFile(file,'utf8'),rows=raw.trim().split('\n').map(JSON.parse);
  assert.equal(rows.length,3);assert.equal(rows[0].page.status,'timeout');
  assert.equal(rows[1].page.status,'error');assert.equal(rows[2].page.status,'not_requested');
  assert.equal(raw.includes('private path or secret'),false);
  assert.equal(observer.summary().capped,1);
 }finally{await rm(root,{recursive:true,force:true})}
});

test('browser probe only reads estimates, persistence state and page heap, retaining unknown values',async()=>{
 const {readPageResources}=await api();let estimateCalls=0,persistedCalls=0;
 const originalNavigator=Object.getOwnPropertyDescriptor(globalThis,'navigator');
 const originalLocation=Object.getOwnPropertyDescriptor(globalThis,'location');
 const originalPerformance=Object.getOwnPropertyDescriptor(globalThis,'performance');
 try{
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{storage:{
   estimate:async()=>{estimateCalls++;return {usage:8192,quota:1048576,usageDetails:{indexedDB:4096}}},
   persisted:async()=>{persistedCalls++;return false},
   persist:()=>{throw Error('must not request persistence')}
  }}});
  Object.defineProperty(globalThis,'location',{configurable:true,value:{origin:'http://127.0.0.1:5173'}});
  Object.defineProperty(globalThis,'performance',{configurable:true,value:{memory:{usedJSHeapSize:16,totalJSHeapSize:32,jsHeapSizeLimit:64}}});
  const row=await readPageResources();
  assert.equal(estimateCalls,1);assert.equal(persistedCalls,1);assert.equal(row.originStorage.usageBytes,8192);
  assert.equal(row.originStorage.persisted,false);assert.equal(row.mainPageJsHeap.usedBytes,16);
  globalThis.navigator.storage.estimate=async()=>{throw Error('unavailable')};
  const failed=await readPageResources();
  assert.equal(failed.originStorage.usageBytes,null);assert.equal(failed.originStorage.quotaBytes,null);
  assert.equal(failed.originStorage.estimateStatus,'error');assert.equal(failed.originStorage.persisted,false);
 }finally{
  for(const [name,descriptor] of [['navigator',originalNavigator],['location',originalLocation],['performance',originalPerformance]]){
   if(descriptor)Object.defineProperty(globalThis,name,descriptor);else delete globalThis[name];
  }
 }
});

test('failure metadata is allowlisted and sanitized before writing encrypted evidence input',async()=>{
 const {createResourceObserver}=await api();const root=await mkdtemp(join(tmpdir(),'audit-observer-'));
 try{
  const file=join(root,'resources.jsonl');const observer=createResourceObserver({file,paths:[]});
  await observer.observe('blob_failure',{metadata:{errorText:'net::ERR_BLOB_OUT_OF_MEMORY',blobUrl:'blob:http://127.0.0.1:5173/id?token=private',password:'never-serialize'}});
  const raw=await readFile(file,'utf8'),row=JSON.parse(raw);
  assert.equal(row.metadata.errorText,'net::ERR_BLOB_OUT_OF_MEMORY');
  assert.equal(row.metadata.blobUrl,'blob:http://127.0.0.1:5173/id');
  assert.equal(raw.includes('never-serialize'),false);assert.equal(raw.includes('token=private'),false);
 }finally{await rm(root,{recursive:true,force:true})}
});
