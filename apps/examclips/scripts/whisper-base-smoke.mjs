import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const executable=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser',chromium.executablePath()].filter(Boolean).find(existsSync);
if(!executable)throw Error('Chrome unavailable');
const browser=await chromium.launch({headless:true,executablePath:executable,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage();
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const result=await page.evaluate(async()=>{
  const {getTranscriber}=await import('/src/asr.js');
  const logs=[];const {transcriber,deviceName}=await getTranscriber(x=>{
   if(logs.length<12)logs.push(x);
  },'base');
  const pcm=new Float32Array(16000*3);
  for(let i=0;i<pcm.length;i++)pcm[i]=.02*Math.sin(Math.PI*2*200*i/16000);
  const decoded=await transcriber(pcm,{task:'transcribe',return_timestamps:true});
  return {backend:deviceName,outputType:typeof decoded?.text,logs};
 });
 assert.equal(result.outputType,'string');
 console.log('WHISPER_BASE_BROWSER_SUCCESS',JSON.stringify({backend:result.backend,progressEvents:result.logs.length}));
}finally{await browser.close()}
