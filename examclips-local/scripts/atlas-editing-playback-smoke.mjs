import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';

const executablePath=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/usr/bin/chromium',chromium.executablePath()].filter(Boolean).find(existsSync);
const browser=await chromium.launch({executablePath,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const origin=process.env.EXAMCLIPS_ORIGIN||'http://127.0.0.1:5173/';
const project={schema:2,videoName:'test-fixture.mp4',duration:4,
 clips:[{id:'edl-playback',title:'Проверка составного урока',start:.2,end:3.8,
 segments:[{start:.2,end:1.2},{start:2,end:3.8}],layout:'hybrid',focusX:50,status:'approved'}],
 chunks:[{start:.2,end:1.2,text:'Первый исходный отрывок.'},{start:2,end:3.8,text:'Второй исходный отрывок.'}],
 activeTab:'clip',ui:{detailOpen:true}};
const errors=[];
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(origin);
 await page.locator('#project-file').setInputFiles({name:'playback.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(project))});
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results');
 await page.locator('#video-file').setInputFiles('test-fixture.mp4');
 await page.waitForFunction(()=>document.querySelector('#player').readyState>=2);
 await page.evaluate(()=>{
  const ctx=document.querySelector('#preview').getContext('2d'),original=ctx.clearRect.bind(ctx);
  window.pausedDraws=0;ctx.clearRect=(...args)=>{window.pausedDraws++;return original(...args)};
 });
 await page.waitForTimeout(300);
 const pausedBefore=await page.evaluate(()=>window.pausedDraws);
 await page.waitForTimeout(300);
 assert.equal(await page.evaluate(()=>window.pausedDraws),pausedBefore,'Paused preview must not redraw continuously');
 await page.locator('#player').evaluate(video=>{video.pause();video.currentTime=2.6});
 await page.locator('#atlas-play').click();
 const resumed=await page.locator('#player').evaluate(video=>({time:video.currentTime,paused:video.paused}));
 assert.ok(resumed.time>=2.55&&resumed.time<3.5&&!resumed.paused,'Resume must retain the current source part: '+JSON.stringify(resumed));
 await page.locator('#atlas-play').click();
 await page.locator('#player').evaluate(video=>{video.pause();video.currentTime=.8});
 await page.locator('#atlas-play-source').click();
 await page.waitForFunction(()=>document.querySelector('#player').currentTime>1.4);
 const source=await page.locator('#player').evaluate(video=>({time:video.currentTime,paused:video.paused}));
 assert.ok(!source.paused&&source.time<2,'Original playback must cross an excluded source gap without jumping: '+JSON.stringify(source));
 await page.locator('#player').evaluate(video=>video.pause());
 // Audio must still follow the EDL when the browser suspends rendering.
 await page.evaluate(()=>new Promise(resolve=>{
  window.atlasOriginalRaf=window.requestAnimationFrame;
  window.requestAnimationFrame=callback=>{window.atlasPendingFrame=callback;resolve();return 0};
 }));
 await page.locator('#catalog-preview-play').evaluate(button=>button.click());
 await page.waitForFunction(()=>document.querySelector('#player').currentTime>1.45,null,{polling:50});
 const background=await page.locator('#player').evaluate(video=>video.currentTime);
 assert.ok(background>=2,'EDL must skip excluded speech even with animation callbacks suspended: '+background);
 await page.evaluate(()=>{
  document.querySelector('#player').pause();
  window.requestAnimationFrame=window.atlasOriginalRaf;
  if(window.atlasPendingFrame)window.requestAnimationFrame(window.atlasPendingFrame);
 });
 await page.locator('#microtopic-attach-file').setInputFiles('test-fixture.mp4');
 assert.ok(await page.locator('#microtopic-final-panel').isVisible());
 await page.locator('#atlas-edit-toggle').click();
 await page.locator('.story-piece').last().getByRole('button',{name:'Удалить отрывок из ролика'}).click();
 assert.equal(await page.locator('.story-piece').count(),1);
 assert.ok(await page.locator('#microtopic-final-panel').isHidden(),'An EDL change must invalidate the old finished MP4');
 assert.equal(await page.locator('#microtopic-final-video').getAttribute('src'),null);
 assert.equal(await page.locator('#approve-topic').getAttribute('aria-pressed'),'false');
 await page.locator('#microtopic-attach-file').setInputFiles('test-fixture.mp4');
 assert.ok(await page.locator('#microtopic-final-panel').isVisible());
 await page.locator('#style-theme').selectOption('midnight');
 assert.ok(await page.locator('#microtopic-final-panel').isHidden(),'Changing composition must also invalidate the finished MP4');
 const repeated=await browser.newPage({viewport:{width:1440,height:1000}});
 repeated.on('pageerror',e=>errors.push(e.message));
 await repeated.goto(origin);
 const repeatedProject={...project,clips:[{...project.clips[0],segments:[{start:.2,end:1.2},{start:.2,end:1.2},{start:2.5,end:3.8}]}]};
 await repeated.locator('#project-file').setInputFiles({name:'repeated.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(repeatedProject))});
 await repeated.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results');
 await repeated.locator('#video-file').setInputFiles('test-fixture.mp4');
 await repeated.waitForFunction(()=>document.querySelector('#player').readyState>=2);
 await repeated.locator('#atlas-edit-toggle').click();
 await repeated.locator('.story-piece').nth(1).getByRole('button',{name:'Воспроизвести этот отрывок'}).click();
 await repeated.locator('#player').evaluate(video=>{video.pause();video.currentTime=.65});
 await repeated.locator('#atlas-play').click();
 await repeated.waitForFunction(()=>{const t=document.querySelector('#player').currentTime;return t<.4||t>=2.5},null,{polling:25});
 const repeatPosition=await repeated.locator('#player').evaluate(video=>video.currentTime);
 assert.ok(repeatPosition>=2.5,'Resuming the second occurrence must continue to the third EDL part: '+repeatPosition);
 assert.deepEqual(errors,[]);
 console.log('ATLAS_EDITING_PLAYBACK_SUCCESS: pause/resume retains EDL position including repeated intervals; source playback crosses gaps; background clip playback skips gaps; edits invalidate previous MP4 and approval');
}finally{await browser.close()}
