import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
const chrome=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser',chromium.executablePath()].filter(Boolean).find(existsSync);
if(!chrome)throw Error('Chrome unavailable');
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({viewport:{width:1280,height:900}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
try{
 await page.addInitScript(()=>{
  window.__batchRecords=[];
  window.showDirectoryPicker=async()=>({
   getFileHandle:async(name)=>({
     createWritable:async()=>{
       const writes=[];
       return new WritableStream({
         write:async chunk=>{
           if(chunk.type!=='write'||!Number.isFinite(chunk.position))
             throw Error('Expected MediaBunny positional StreamTarget chunk');
           writes.push({position:chunk.position,data:new Uint8Array(chunk.data)});
         },
         close:async()=>{
           const length=Math.max(0,...writes.map(w=>w.position+w.data.length));
           const bytes=new Uint8Array(length);
           for(const part of writes)bytes.set(part.data,part.position);
           window.__batchRecords.push({name,size:bytes.length,signature:String.fromCharCode(...bytes.slice(4,8))});
         }
       });
     }
   })
  });
 });
 await page.goto('http://127.0.0.1:5173/');
 await page.locator('#atlas-new-lecture').click();
 await page.locator('#video-file').setInputFiles(resolve('test-fixture.mp4'));
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:30000});
 await page.locator('#wizard-next').click();
 await page.locator('#wizard-next').click();
 await page.locator('#srt-file').setInputFiles(resolve('test-fixture.srt'));
 await page.waitForFunction(()=>document.querySelector('#workflow-start')?.textContent.includes('SRT'));
 await page.locator('#workflow-start').click();
 await page.waitForFunction(()=>!document.querySelector('#export-all').disabled,{timeout:30000});
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 await page.locator('.microtopic-card-title').first().click();
 await page.locator('#atlas-edit-toggle').click();
 await page.locator('#add').click();
 await page.locator('.top-navigation [data-editor-tab="export"]').click();
 await page.locator('#export-all').click();
 await page.waitForFunction(()=>document.querySelector('#progress')?.textContent.includes('Экспортировано 2'),{timeout:150000});
 const result=await page.evaluate(()=>window.__batchRecords);
 assert.equal(result.length,2);
 for(const file of result){
  assert.ok(file.size>5000,file.name);
  assert.equal(file.signature,'ftyp',file.name);
  assert.match(file.name,/\.mp4$/);
 }
 assert.deepEqual(errors,[]);
 console.log('BATCH_LOCAL_EXPORT_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
