import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const browserPath=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!browserPath)throw Error('Chrome unavailable');
const browser=await chromium.launch({headless:true,executablePath:browserPath,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({viewport:{width:1380,height:1000}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const cap=await page.evaluate(async()=>await (await fetch('/api/local-ocr-capabilities')).json());
 assert.equal(cap.available,true,JSON.stringify(cap));
 for(const [file,lang,expected] of [
  ['ocr_benchmark_results/lecture_ui_en.png','en','Explore how each method works'],
  ['ocr_benchmark_results/lecture_board_ru.png','ru','Как работают контейнеры']
 ]){
   const base64=readFileSync(file).toString('base64');
   const result=await page.evaluate(async ({base64,lang})=>{
     const image=new Image();
     image.src='data:image/png;base64,'+base64;await image.decode();
     const canvas=document.createElement('canvas');
     canvas.width=image.width;canvas.height=image.height;
     const context=canvas.getContext('2d',{willReadFrequently:true});
     context.drawImage(image,0,0);
     const {recognizeEducationalFrame}=await import('/src/scene-analysis.js');
     const {analyzeSlideContext}=await import('/src/slide-context.js');
     const detected=await recognizeEducationalFrame(canvas,{language:lang,engine:'rapid'});
     const pixels=context.getImageData(0,0,canvas.width,canvas.height).data;
     const slide=analyzeSlideContext(detected.lines,canvas.width,canvas.height,
       {sampleRgb:(x,y)=>[pixels[(y*canvas.width+x)*4],pixels[(y*canvas.width+x)*4+1],pixels[(y*canvas.width+x)*4+2]]});
     return {engine:detected.engine,lines:detected.lines.length,title:slide.title,tabs:slide.tabs.map(t=>t.text),active:slide.activeTab};
   },{base64,lang});
   assert.ok(result.engine.startsWith('PP-OCR'),JSON.stringify(result));
   assert.ok(result.lines>=3,JSON.stringify(result));
   assert.ok(result.title.includes(expected),JSON.stringify(result));
   if(lang==='en'){
      assert.ok(result.tabs.includes('PySINDy')&&result.tabs.includes('Overview'),JSON.stringify(result));
      assert.equal(result.active,'Overview');
   }
   console.log('LOCAL_OCR_BROWSER_SUCCESS',lang,JSON.stringify(result));
 }
 // An unrelated website cannot send cross-origin OCR requests to a user's local Vite server.
 const external=await fetch('http://127.0.0.1:5173/api/local-ocr',{
   method:'POST',headers:{Origin:'https://external-attacker.example','Content-Type':'application/json'},
   body:JSON.stringify({language:'en',png_base64:readFileSync('ocr_benchmark_results/lecture_ui_en.png').toString('base64')})
 });
 assert.equal(external.status,403);
 assert.deepEqual(errors,[]);
}finally{await browser.close()}
