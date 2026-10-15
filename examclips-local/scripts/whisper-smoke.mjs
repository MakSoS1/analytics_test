import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('Chrome is not installed');
const browser=await chromium.launch({headless:true,executablePath:chrome,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({acceptDownloads:false});
const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('response',r=>{if(r.status()>=400)console.log('FAILED_RESOURCE',r.status(),r.url().slice(0,500))});page.on('console',m=>{if(m.type()==='error')console.log('CHROME_CONSOLE_ERROR',m.text().slice(0,300))});
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const result=await page.evaluate(async()=>{
   const {getTranscriber}=await import('/src/asr.js');
   const statuses=[];let p;
   try {p=await getTranscriber(s=>{if(statuses.length<15)statuses.push(s);console.log('ASR_STATUS',s)})}
   catch(e){console.error('ASR_INIT_FAILURE',JSON.stringify(statuses),String(e));throw e}
   const audio=new Float32Array(16000*3);
   const ret=await p.transcriber(audio,{task:'transcribe',return_timestamps:true});
   return {engine:p.deviceName,transcript:ret?.text||'',chunks:ret?.chunks?.length||0,statuses};
 });
 assert.ok(result.engine==='wasm'||result.engine==='webgpu');assert.equal(typeof result.transcript,'string');
 assert.deepEqual(errors,[]);
 console.log('WHISPER_BROWSER_SMOKE_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
