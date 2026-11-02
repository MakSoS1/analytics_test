// User-device only. Intermediate ASR output never contacts the application server.
const DB_NAME='examclips-asr-cache-v1',STORE='checkpoints';
export function normalizeCheckpoint(raw,duration){
 const chunks=(raw?.chunks||[]).filter(c=>c&&Number.isFinite(c.start)&&Number.isFinite(c.end)
 &&typeof c.text==='string'&&c.start>=0&&c.end>c.start&&c.end<=duration+.01)
 .sort((a,b)=>a.start-b.start);
 const done=[...new Set((raw?.completedWindows||[])
   .filter(x=>Number.isInteger(x)&&x>=0&&x<duration&&x%30===0))].sort((a,b)=>a-b);
 return {chunks,completedWindows:done};
}
export function remainingWindows(duration,limit=Infinity,completedWindows=[]){
 const total=Math.min(duration,limit),done=new Set(completedWindows),pending=[];
 for(let start=0;start<total;start+=30)if(!done.has(start))pending.push(start);
 return pending;
}
async function database(){
 if(!('indexedDB' in globalThis))throw Error('IndexedDB не поддерживается');
 return await new Promise((resolve,reject)=>{
  const request=indexedDB.open(DB_NAME,1);
  request.onupgradeneeded=()=>request.result.createObjectStore(STORE);
  request.onerror=()=>reject(request.error);
  request.onsuccess=()=>resolve(request.result);
 });
}
export async function checkpointKey(file,language){
 if(!file||typeof file.slice!=='function')throw Error('Не выбран исходный файл');
 const start=await file.slice(0,65536).arrayBuffer();
 const end=await file.slice(Math.max(0,file.size-65536),file.size).arrayBuffer();
 const fingerprint=new Uint8Array(start.byteLength+end.byteLength);
 fingerprint.set(new Uint8Array(start));fingerprint.set(new Uint8Array(end),start.byteLength);
 const hash=await crypto.subtle.digest('SHA-256',fingerprint);
 const hex=Array.from(new Uint8Array(hash).slice(0,12),b=>b.toString(16).padStart(2,'0')).join('');
 return [file.size,file.lastModified||0,language,hex].join(':');
}
export async function loadCheckpoint(key,duration){
 const db=await database();
 try{
  return await new Promise((resolve,reject)=>{
   const t=db.transaction(STORE,'readonly'),q=t.objectStore(STORE).get(key);
   q.onsuccess=()=>resolve(normalizeCheckpoint(q.result,duration));
   q.onerror=()=>reject(q.error);
  });
 }finally{db.close()}
}
export async function saveCheckpoint(key,data){
 const db=await database();
 try{
  return await new Promise((resolve,reject)=>{
   const t=db.transaction(STORE,'readwrite');
   t.objectStore(STORE).put(data,key);
   t.oncomplete=()=>resolve(true);t.onerror=()=>reject(t.error);
  });
 }finally{db.close()}
}
export async function deleteCheckpoint(key){
 const db=await database();
 try{
  return await new Promise((resolve,reject)=>{
   const t=db.transaction(STORE,'readwrite');t.objectStore(STORE).delete(key);
   t.oncomplete=()=>resolve(true);t.onerror=()=>reject(t.error);
  });
 }finally{db.close()}
}
