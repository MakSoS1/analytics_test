import {chromium} from 'playwright-core';
import {execFileSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('No Chrome installation');
const work=process.cwd();
const fixture=resolve(work,'presenter-motion-fixture.mp4');
const subtitle=resolve(work,'test-fixture.srt');
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({acceptDownloads:true});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
function samplePixels(seconds,filename){
  return execFileSync('ffmpeg',['-loglevel','error','-ss',String(seconds),'-i',filename,'-frames:v','1',
    '-vf','crop=235:160:395:998,scale=128:96','-f','rawvideo','-pix_fmt','gray','pipe:1'],{maxBuffer:10e6});
}
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 await page.locator('#video-file').setInputFiles(fixture);
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled);
 await page.locator('#srt-file').setInputFiles(subtitle);
 await page.waitForFunction(()=>!document.querySelector('#export').disabled);
 await page.locator('.controls .detail-settings summary').click();
  await page.locator('#layout').selectOption('hybrid');
 const [download]=await Promise.all([page.waitForEvent('download',{timeout:90000}),page.locator('#export').click()]);
 const file=resolve(work,'presenter-motion-export.mp4');await download.saveAs(file);
 const a=samplePixels(.6,file),b=samplePixels(2.6,file);
 assert.equal(a.length,b.length);
 let sum=0;for(let i=0;i<a.length;i++)sum+=Math.abs(a[i]-b[i]);
 const mean=sum/a.length;
 assert.ok(mean>2.5,'Presenter picture was frozen: mean motion='+mean);
 const probe=JSON.parse(execFileSync('ffprobe',['-v','error','-show_entries','stream=codec_type','-of','json',file],{encoding:'utf-8'}));
 assert.ok(probe.streams.some(s=>s.codec_type==='audio'),'Presenter test output must have source audio');
 assert.deepEqual(errors,[]);
 console.log('LIVE_PRESENTER_MOTION_SUCCESS',{meanPixelDifference:mean,audio:true});
}finally{await browser.close()}
