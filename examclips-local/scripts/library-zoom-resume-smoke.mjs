import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
const executablePath=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!executablePath)throw Error('Chrome not installed');
const browser=await chromium.launch({executablePath,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const errors=[];
try{
 const page=await browser.newPage({viewport:{width:1440,height:960},acceptDownloads:true});
 page.on('pageerror',e=>errors.push(e.message));
 page.on('framenavigated',frame=>{if(frame===page.mainFrame())console.log('STORAGE_TEST_NAVIGATED',frame.url())});
 await page.goto('http://127.0.0.1:5173/');
 await page.evaluate(()=>localStorage.setItem('__persistence_probe','persistent'));
 assert.ok(await page.locator('#library-section').isVisible());
 await page.locator('#video-file').setInputFiles('test-fixture.mp4');
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled);
 await page.locator('#srt-file').setInputFiles('test-fixture.srt');
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results');
 assert.ok(await page.locator('#back-to-library').isVisible());
 assert.ok(await page.locator('#timeline-zoom-in').isVisible());
 for(let i=0;i<7;i++)await page.locator('#timeline-zoom-in').click();
 assert.equal(await page.locator('#timeline-zoom-label').textContent(),'8×');
 const metrics=await page.evaluate(()=>({
   inner:document.querySelector('#timeline-canvas').scrollWidth,
   viewport:document.querySelector('#timeline-viewport').clientWidth
 }));
 assert.ok(metrics.inner>=metrics.viewport*7,'Timeline did not zoom: '+JSON.stringify(metrics));
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 await page.locator('#clip-title').fill('Сохранённая тема Docker');
 await page.locator('.top-navigation [data-editor-tab="timeline"]').click();
 console.log('AUTOSAVE_INITIAL_STATE',await page.evaluate(()=>({
  note:document.querySelector('#autosave-state').textContent,
  id:localStorage.getItem('examclips-current-project-id'),
  phase:document.querySelector('#app')?.dataset.phase
 })));
 await page.waitForFunction(()=>!!localStorage.getItem('examclips-current-project-id'),null,{timeout:12000});
 await page.waitForFunction(async()=>{
  const m=await import('/src/project-library.js');
  const entries=await m.listLibraryProjects();
  return entries.length===1&&entries[0].snapshot.clips[0]?.title==='Сохранённая тема Docker';
 },null,{timeout:12000});
 await page.waitForFunction(async()=>{
  const m=await import('/src/project-library.js');
  const entries=await m.listLibraryProjects();
  return entries.length>0&&!!(await m.getCachedOriginal(entries[0].id));
 },{timeout:12000});
 console.log('AUTOSAVE_FINAL_STATE',await page.evaluate(()=>({
   text:document.querySelector('#autosave-state')?.textContent,
   id:localStorage.getItem('examclips-current-project-id')
 })));
 const beforeReload=await page.evaluate(async()=>{
  const m=await import('/src/project-library.js');
  return {saveText:document.querySelector('#autosave-state')?.textContent,phase:document.querySelector('#app')?.dataset.phase,probe:localStorage.getItem('__persistence_probe'),url:location.href,origin:location.origin,localId:localStorage.getItem('examclips-current-project-id'),
   projects:(await m.listLibraryProjects()).map(x=>x.id),
   dbs:await indexedDB.databases()};
 });
 console.log('BEFORE_RELOAD_DIAGNOSTICS',JSON.stringify(beforeReload));
 await page.reload();
 try{await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='results',{timeout:12000})}
 catch(err){
  const diagnostics=await page.evaluate(async()=>{
   const m=await import('/src/project-library.js'),entries=await m.listLibraryProjects();
   return {probe:localStorage.getItem('__persistence_probe'),url:location.href,origin:location.origin,dbs:await indexedDB.databases(),phase:document.querySelector('#app')?.dataset.phase,
    status:document.querySelector('#autosave-state')?.textContent,
    note:document.querySelector('#file-note')?.textContent,
    last:localStorage.getItem('examclips-current-project-id'),
    entries:await Promise.all(entries.map(async e=>{
      const file=await m.getCachedOriginal(e.id);
      return {id:e.id,title:e.title,meta:e.source,
       cached:!!file,cachedMeta:m.pickFileMetadata(file),
       same:m.sameVideoFile(e.source,file)};
    }))};
  });
  console.error('AUTORESTORE_DIAGNOSTICS',JSON.stringify(diagnostics),errors);
  throw err
 }
 assert.equal(await page.locator('#timeline-zoom-label').textContent(),'8×');
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 assert.equal(await page.locator('#clip-title').inputValue(),'Сохранённая тема Docker');
 // Return immediately after an edit, BEFORE the 550ms debounce expires.
 // A pre-existing in-flight IndexedDB save must not overwrite this latest title.
 await page.locator('#clip-title').fill('Docker — быстрый переход с сохранением');
 await page.locator('#back-to-library').click();
 await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='upload');
 assert.ok(await page.locator('#library-section').isVisible());
 assert.equal(await page.locator('.library-item').count(),1);
 await page.locator('.library-item-actions button').first().click();
 await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='results');
 assert.equal(await page.locator('#timeline-zoom-label').textContent(),'8×');
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 assert.equal(await page.locator('#clip-title').inputValue(),'Docker — быстрый переход с сохранением');
 assert.deepEqual(errors,[]);
 console.log('LIBRARY_RELOAD_ZOOM_SUCCESS',JSON.stringify({
  projects:1,zoom:8,restoredTitle:'Docker — быстрый переход с сохранением',
  widthRatio:metrics.inner/metrics.viewport
 }));
}finally{await browser.close()}
