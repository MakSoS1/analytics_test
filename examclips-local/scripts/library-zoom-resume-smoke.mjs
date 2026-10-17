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
 await page.goto('http://127.0.0.1:5173/');
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
 await page.waitForFunction(async()=>{
  const m=await import('/src/project-library.js');
  const entries=await m.listLibraryProjects();
  return entries.length===1&&entries[0].snapshot.clips[0]?.title==='Сохранённая тема Docker';
 },{timeout:12000});
 await page.waitForFunction(async()=>{
  const m=await import('/src/project-library.js');
  const entries=await m.listLibraryProjects();
  return entries.length>0&&!!(await m.getCachedOriginal(entries[0].id));
 },{timeout:12000});
 await page.reload();
 await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='results',{timeout:20000});
 assert.equal(await page.locator('#timeline-zoom-label').textContent(),'8×');
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 assert.equal(await page.locator('#clip-title').inputValue(),'Сохранённая тема Docker');
 await page.locator('#back-to-library').click();
 await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='upload');
 assert.ok(await page.locator('#library-section').isVisible());
 assert.equal(await page.locator('.library-item').count(),1);
 await page.locator('.library-item-actions button').first().click();
 await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='results');
 assert.equal(await page.locator('#timeline-zoom-label').textContent(),'8×');
 assert.deepEqual(errors,[]);
 console.log('LIBRARY_RELOAD_ZOOM_SUCCESS',JSON.stringify({
  projects:1,zoom:8,restoredTitle:'Сохранённая тема Docker',
  widthRatio:metrics.inner/metrics.viewport
 }));
}finally{await browser.close()}
