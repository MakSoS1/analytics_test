import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
// Loads the single on-device speech model (Parakeet TDT 0.6B v3) in Chrome and
// decodes three seconds of silence. Downloads public weights on first run.
const chrome=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser',chromium.executablePath()].filter(Boolean).find(existsSync);
if(!chrome)throw Error('Chrome is not installed');
const browser=await chromium.launch({headless:true,executablePath:chrome,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({acceptDownloads:false});
const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('response',r=>{if(r.status()>=400)console.log('FAILED_RESOURCE',r.status(),r.url().slice(0,500))});page.on('console',m=>{if(m.type()==='error')console.log('CHROME_CONSOLE_ERROR',m.text().slice(0,300))});
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const result=await page.evaluate(async()=>{
   const {getTranscriber,ASR_MODEL}=await import('/src/asr.js');
   const statuses=[];
   const p=await getTranscriber(s=>{if(statuses.length<15&&!/%$/.test(s))statuses.push(s)});
   const ret=await p.transcriber.transcribe(new Float32Array(16000*3),16000,{returnTimestamps:true});
   return {model:ASR_MODEL,engine:p.deviceName,transcript:ret?.utterance_text??'',words:ret?.words?.length??0,statuses};
 });
 assert.ok(result.engine==='wasm'||result.engine==='webgpu');assert.equal(typeof result.transcript,'string');
 assert.deepEqual(errors,[]);
 console.log('ASR_BROWSER_SMOKE_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
