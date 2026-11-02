import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
const executablePath=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',chromium.executablePath()].filter(Boolean).find(existsSync);
const browser=await chromium.launch({executablePath,headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage();await page.goto('http://127.0.0.1:5173/');
 const result=await page.evaluate(async()=>{
  const {paintHybrid}=await import('/src/composition.js');
  const source=document.createElement('canvas');source.width=400;source.height=400;
  const x=source.getContext('2d');x.fillStyle='#ff0000';x.fillRect(0,0,200,400);x.fillStyle='#00ff00';x.fillRect(200,0,200,400);
  const canvas=document.createElement('canvas');canvas.width=720;canvas.height=1280;
  const ctx=canvas.getContext('2d'),texts=[],original=ctx.fillText.bind(ctx);
  ctx.fillText=(text,...rest)=>{texts.push(text);original(text,...rest)};
  const spec={version:2,title:'One coherent explanation',hideSpeaker:true,speaker:{x:0,y:0,w:.1,h:.1},
   panels:[{id:'one',rect:{x:0,y:0,w:.5,h:1},sourceOnly:true},{id:'two',rect:{x:.5,y:0,w:.5,h:1},sourceOnly:true}],beats:[{time:0,focus:0},{time:8,focus:1}]};
  function sample(time,lesson=time){texts.length=0;paintHybrid(canvas,source,400,400,'',spec,time,lesson);const rgba=ctx.getImageData(0,0,720,1280).data;let red=0,green=0;
   for(let i=0;i<rgba.length;i+=4){if(rgba[i]>150&&rgba[i+1]<40)red++;if(rgba[i+1]>150&&rgba[i]<40)green++}
   return {red,green,texts:[...texts]};}
  return {intro:sample(0),first:sample(3),second:sample(10),secondPiece:sample(0,30)};
 });
 assert.ok(result.intro.texts.some(t=>t.includes('coherent')));
 assert.ok(result.first.red>10000);assert.equal(result.first.green,0);
 assert.ok(result.second.green>10000);assert.equal(result.second.red,0);
 assert.equal(result.first.texts.length,0);assert.equal(result.secondPiece.texts.length,0);
 console.log('SINGLE_FOCUS_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
