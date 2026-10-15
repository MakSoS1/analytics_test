import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('Chrome unavailable');
const browser=await chromium.launch({headless:true,executablePath:chrome,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({viewport:{width:1280,height:850}});
page.on('pageerror',e=>console.log('PAGE_ERROR',e.message));
try{
 await page.goto('http://127.0.0.1:5173/');
 const r=await page.evaluate(async()=>{
   const {analyzeScene}=await import('/src/scene-analysis.js');
   const fake={width:1600,height:900,duration:60,videoSink:{getSample:async()=>({
      draw:(ctx)=>{
        ctx.fillStyle='#fff';ctx.fillRect(0,0,1600,900);
        ctx.fillStyle='#101010';ctx.font='bold 69px Arial';ctx.fillText('Docker Networking',80,110);
        ctx.font='bold 42px Arial';ctx.fillText('Single Host Networking',80,405);
        ctx.fillText('Multi Host Networking',80,490);
        ctx.font='bold 37px Arial';ctx.fillText('Default bridge docker0',990,300);
        ctx.fillText('Docker networks bridge overlay',990,365);
      },close:()=>{}
   })}};
   const progress=[];
   const {scene,recognizedLines,note}=await analyzeScene(fake,{start:0,end:40},
      [{start:4,end:9,text:'single host networking'},{start:16,end:20,text:'docker networks bridge overlay'}],
      {language:'en',onProgress:x=>{if(progress.length<6)progress.push(x)}});
   return {scene,recognizedLines,note,progress};
 });
 console.log('OCR_RESULT',JSON.stringify({lines:r.recognizedLines,method:r.scene.method,title:r.scene.title,regions:r.scene.panels.map(p=>({bbox:p.rect,ocr:p.text.slice(0,100)}))}));
 assert.ok(r.recognizedLines>=2,'OCR needs to find labels on synthetic educational slide');
 assert.equal(r.scene.method,'ocr-assisted-original-crops');
 assert.ok(r.scene.panels[0].text.length>0&&r.scene.panels[1].text.length>0);
 console.log('HYBRID_OCR_SMOKE_SUCCESS');
}finally{await browser.close()}
