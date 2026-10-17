import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
const executable=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!executable)throw Error('Chrome unavailable for editorial screenshots');
const browser=await chromium.launch({headless:true,executablePath:executable,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({viewport:{width:1100,height:1450}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const result=await page.evaluate(async()=>{
   const {paintHybrid}=await import('/src/composition.js');
   const {makeStoryboard}=await import('/src/scene-model.js');
   const canvas=document.createElement('canvas');canvas.id='editorial-canvas';canvas.width=720;canvas.height=1280;
   // Keep the application DOM intact: its asynchronous startup may still update UI nodes.
   // The visual QA captures only this dedicated canvas, not the surrounding page.
   document.body.appendChild(canvas);
   const slide=document.createElement('canvas');slide.width=1600;slide.height=900;
   const x=slide.getContext('2d');
   x.fillStyle='#fff';x.fillRect(0,0,1600,900);x.fillStyle='#1A263D';x.font='bold 72px Arial';x.fillText('Docker Networking',65,110);
   x.font='bold 40px Arial';x.fillText('Single host networking',90,325);x.fillText('Multi host networking',1000,325);
   x.strokeStyle='#5274AB';x.lineWidth=9;x.beginPath();x.moveTo(250,380);x.lineTo(250,440);x.lineTo(150,520);x.moveTo(250,440);x.lineTo(380,520);x.stroke();
   x.fillStyle='#C6DCF5';x.fillRect(88,535,260,150);x.fillRect(1010,535,280,150);
   x.fillStyle='#243B65';x.font='bold 40px Arial';x.fillText('bridge',150,630);x.fillText('overlay',1050,630);
   x.fillStyle='#E5E2D7';x.fillRect(1250,735,320,160);
   x.fillStyle='#37465B';x.beginPath();x.arc(1410,787,40,0,7);x.fill();x.fillRect(1337,826,150,73);
   const scene=makeStoryboard({width:1600,height:900,duration:30,lines:[],titleOverride:'Docker Networking'});
   scene.panels=[
     {id:'left',label:'Network architecture',rect:{x:.03,y:.18,w:.56,h:.63},lines:['Single host networking','Bridge interface']},
     {id:'right',label:'Объяснение',rect:{x:.61,y:.18,w:.36,h:.63},
       lines:['Docker bridge connects containers inside one host',
         'The default bridge interface is named docker0',
         'Overlay networking connects workloads across multiple hosts',
         'Each connection has its own isolation and routing rules']}
   ];
   scene.beats=[{time:0,focus:0},{time:7,focus:1}];
   scene.speaker={x:.78,y:.81,w:.21,h:.18};
   window.__draw=(time,theme)=>{
     scene.theme=theme;
     paintHybrid(canvas,slide,1600,900,
       'Контейнеры можно объединять в виртуальные сети',scene,time);
     return [...canvas.getContext('2d').getImageData(0,0,720,1280).data];
   };
   return {width:canvas.width,height:canvas.height,beats:scene.beats.length};
 });
 assert.equal(result.width,720);
 const first=await page.evaluate(()=>window.__draw(2,'warm'));
 await page.locator('#editorial-canvas').screenshot({path:resolve('editorial-diagram.png')});
 const second=await page.evaluate(()=>window.__draw(9,'warm'));
 await page.locator('#editorial-canvas').screenshot({path:resolve('editorial-reflow.png')});
 let different=0;
 for(let i=0;i<first.length;i+=16){
   if(Math.abs(first[i]-second[i])+Math.abs(first[i+1]-second[i+1])+Math.abs(first[i+2]-second[i+2])>36)different++;
 }
 const fraction=different/(first.length/16);
 assert.ok(fraction>.03,'Editorial focus change must visibly alter teaching content: '+fraction);
 await page.evaluate(()=>window.__draw(9,'midnight'));
 await page.locator('#editorial-canvas').screenshot({path:resolve('editorial-dark.png')});
 assert.deepEqual(errors,[]);
 console.log('EDITORIAL_VISUAL_SMOKE_SUCCESS',JSON.stringify({changedPixelRatio:fraction,frames:3}));
}finally{await browser.close()}
