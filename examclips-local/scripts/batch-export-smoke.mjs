import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('Chrome unavailable');
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({viewport:{width:1280,height:900}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
try{
 await page.addInitScript(()=>{
  window.__batchRecords=[];
  window.showDirectoryPicker=async()=>({
   getFileHandle:async(name)=>({createWritable:async()=>({
    write:async(blob)=>{
     const bytes=new Uint8Array(await blob.arrayBuffer());
     window.__batchRecords.push({name,size:bytes.length,signature:String.fromCharCode(...bytes.slice(4,8))});
    },
    close:async()=>{},abort:async()=>{}
   })})
  });
 });
 await page.goto('http://127.0.0.1:5173/');
 await page.locator('#video-file').setInputFiles(resolve('test-fixture.mp4'));
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:30000});
 await page.locator('#srt-file').setInputFiles(resolve('test-fixture.srt'));
 await page.waitForFunction(()=>!document.querySelector('#export-all').disabled,{timeout:30000});
 await page.locator('#add').click();
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
