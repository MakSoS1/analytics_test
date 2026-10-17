/**
 * Private project library. Metadata only, NOT original video bytes.
 * IndexedDB is origin-scoped; users must re-link originals unless they opted
 * into a persistent FileSystemFileHandle supported by their browser.
 * All operations reject on errors so the UI cannot claim a save happened.
 */
const DB='examclips-project-library-v1',STORE='projects',MEDIA='sources';
const openDb=()=>new Promise((resolve,reject)=>{
 if(typeof indexedDB==='undefined')return reject(Error('IndexedDB unavailable'));
 const request=indexedDB.open(DB,2);
 request.onupgradeneeded=()=>{const db=request.result;if(!db.objectStoreNames.contains(STORE))
   db.createObjectStore(STORE,{keyPath:'id'});
  if(!db.objectStoreNames.contains(MEDIA))db.createObjectStore(MEDIA);};
 request.onerror=()=>reject(request.error||Error('IndexedDB open failed'));
 request.onsuccess=()=>resolve(request.result);
});
async function operation(mode,fn,storeName=STORE){
 const db=await openDb();
 try{
  return await new Promise((resolve,reject)=>{
    const tx=db.transaction(storeName,mode),store=tx.objectStore(storeName);
    let value;
    tx.oncomplete=()=>resolve(value);
    tx.onabort=()=>reject(tx.error||Error('IndexedDB transaction failed'));
    tx.onerror=()=>reject(tx.error||Error('IndexedDB error'));
    try{fn(store,result=>{value=result})}catch(e){tx.abort();reject(e)}
  });
 }finally{db.close()}
}
const pickFileMetadata=file=>file?{
 name:String(file.name||''),size:Number(file.size||0),modified:Number(file.lastModified||0),
 type:String(file.type||'')
}:null;
export {pickFileMetadata};
export function sameVideoFile(metadata,file){
 return !!metadata&&!!file&&metadata.name===file.name&&
  metadata.size===file.size&&(!metadata.modified||!file.lastModified||metadata.modified===file.lastModified);
}
export function safeProjectSnapshot(snapshot){
 if(!snapshot||!Array.isArray(snapshot.clips)||!Array.isArray(snapshot.chunks))throw Error('Invalid project snapshot');
 const safe={
  schema:2,
  clips:snapshot.clips,
  chunks:snapshot.chunks,
  sceneCuts:Array.isArray(snapshot.sceneCuts)?snapshot.sceneCuts:[],
  selected:Number.isInteger(snapshot.selected)?snapshot.selected:0,
  activeTab:typeof snapshot.activeTab==='string'?snapshot.activeTab:'timeline',
  view:snapshot.view&&typeof snapshot.view==='object'?snapshot.view:{zoom:1,offset:0},
  duration:Number(snapshot.duration)||0
 };
 if(safe.duration<=0||safe.duration>10800)throw Error('Invalid media duration');
 return structuredClone(safe);
}
export async function saveLibraryProject(record){
 if(!record||typeof record.id!=='string'||!record.id||!record.source||!record.snapshot)throw Error('Invalid library project');
 const entry={...record,snapshot:safeProjectSnapshot(record.snapshot)};
 await operation('readwrite',(store)=>store.put(entry));
 return entry.id;
}
export async function listLibraryProjects(){
 return operation('readonly',(store,done)=>{
   const req=store.getAll();req.onsuccess=()=>done(req.result
     .sort((a,b)=>String(b.updatedAt||'').localeCompare(String(a.updatedAt||''))));
 });
}
export async function getLibraryProject(id){
 return operation('readonly',(store,done)=>{
  const r=store.get(id);r.onsuccess=()=>done(r.result||null);
 });
}
export async function deleteLibraryProject(id){
 return operation('readwrite',store=>store.delete(id));
}
export async function wipeLibrary(){
 return operation('readwrite',store=>store.clear());
}

/** Opportunistic same-device copy for small uploads (<64 MiB).
 * Larger lectures never copied into IndexedDB; only timeline metadata is saved.
 */
export async function cacheSmallOriginal(id,file){
 if(!file||file.size>64*1024*1024||file.size===0)return false;
 const usage=await navigator.storage?.estimate?.().catch(()=>null);
 if(usage?.quota&&(usage.quota-(usage.usage||0))<file.size*2)return false;
 try{
  await operation('readwrite',store=>store.put(file,id),MEDIA);
  return true;
 }catch{return false}
}
export async function getCachedOriginal(id){
 return operation('readonly',(store,done)=>{
   const r=store.get(id);r.onsuccess=()=>done(r.result||null);
 },MEDIA);
}
export async function deleteCachedOriginal(id){
 return operation('readwrite',store=>store.delete(id),MEDIA);
}
