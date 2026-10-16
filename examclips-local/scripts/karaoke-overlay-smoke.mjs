import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('Chrome unavailable');
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1100,height:900}});
 await page.goto('http://127.0.0.1:5173/');
 const result=await page.evaluate(async()=>{
  const {paintFrame}=await import('/src/composition.js');
  const {captionSequenceAt}=await import('/src/caption-flow.js');
  const source=document.createElement('canvas');source.width=1600;source.height=900;
  const raw=source.getContext('2d');raw.fillStyle='#d4e4f7';raw.fillRect(0,0,1600,900);
  raw.fillStyle='#32415b';raw.fillRect(1340,670,250,225);
  raw.fillStyle='#ffffff';raw.font='48px Arial';raw.fillText('Docker containers',95,230);
  const canvas=document.createElement('canvas');canvas.width=720;canvas.height=1280;
  const cues=[{start:0,end:3,text:'Docker запускает отдельные контейнеры быстро'}];
  document.body.append(canvas);canvas.id='karaoke-preview';
  const outputs=[];
  for(const instant of [null,.2,2.3]){
   paintFrame(canvas,source,1600,900,'hybrid',50,
       instant===null?null:captionSequenceAt(cues,instant),null,3);
   const ctx=canvas.getContext('2d'),img=ctx.getImageData(55,840,610,110);
   outputs.push(Array.from(img.data));
  }
  const difference=(a,b)=>{
    let sum=0;for(let i=0;i<a.length;i+=4)sum+=Math.abs(a[i]-b[i])+Math.abs(a[i+1]-b[i+1])+Math.abs(a[i+2]-b[i+2]);
    return sum/(a.length/4);
  };
  // Beyond caption glyph area (top left of stage) pixels must be unchanged
  return {diffFromNoSubtitle:difference(outputs[0],outputs[1]),
    diffBetweenSpokenPhrases:difference(outputs[1],outputs[2]),
    emptyCorner:outputs[0].slice(0,3).every((v,i)=>v===outputs[1][i])};
 });
 assert.ok(result.diffFromNoSubtitle>0.5,JSON.stringify(result));
 assert.ok(result.diffBetweenSpokenPhrases>0.5,JSON.stringify(result));
 assert.equal(result.emptyCorner,true);
 await page.locator('#karaoke-preview').screenshot({path:'mvp-karaoke-frame.png'});
 console.log('KARAOKE_OVERLAY_SMOKE_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
