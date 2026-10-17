import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
const executablePath=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
const browser=await chromium.launch({executablePath,headless:true,args:['--no-sandbox']});
const srt=[
 ['00:00:10,000','00:00:28,000','Docker контейнеры позволяют изолировать приложения потому что они используют общее ядро системы. Например изоляция библиотек помогает запускать разные версии одного приложения независимо.'],
 ['00:00:40,000','00:01:00,000','Организационный момент проверка микрофона, подождите минуту. Давайте подождём участников и настроим проектор перед перерывом.'],
 ['00:01:35,000','00:01:56,000','Docker контейнер использует изолированный образ с библиотеками и настройками. Поэтому сервис можно воспроизводимо запускать на разных серверах, не настраивая каждый раз систему вручную.'],
 ['00:02:05,000','00:02:24,000','Окей пока мы ждём, перерыв. Проверка микрофона, подождите минуту и посмотрите расписание следующего занятия.'],
 ['00:02:35,000','00:02:55,000','Например балансировка распределяет сетевые запросы между несколькими сервисами чтобы система продолжала работать под высокой нагрузкой. Это позволяет избежать отказа.']
].map((x,i)=>[i+1,x[0]+' --> '+x[1],x[2],''].join('\n')).join('\n');
try{
 const page=await browser.newPage({viewport:{width:1440,height:900}});
 const errors=[];page.on('pageerror',err=>errors.push(err.message));
 await page.goto('http://127.0.0.1:5173/');
 await page.locator('#video-file').setInputFiles('selective-lecture-fixture.mp4');
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:40000});
 assert.equal(await page.locator('#story-keep').count(),0,'Editorial budget must be removed');
 await page.locator('#srt-file').setInputFiles({name:'sparse.srt',mimeType:'text/plain',buffer:Buffer.from(srt)});
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results',{timeout:40000});
 const result=await page.evaluate(()=>{
  const tracks=[...document.querySelectorAll('#timeline-track .timeline-part.clip')];
  const kept=tracks.map(e=>({left:parseFloat(e.style.left),width:parseFloat(e.style.width),label:e.innerText}));
  const skipped=[...document.querySelectorAll('#timeline-track .timeline-part.skipped')];
  const cover=document.querySelector('#timeline-coverage').textContent;
  return {kept,skipped:skipped.length,coverage:cover,clipCount:document.querySelector('#clip-count').textContent};
 });
 assert.ok(result.kept.length>=1,'No informative candidate was selected: '+JSON.stringify(result));
 assert.ok(result.skipped>=2,'Source gaps missing: '+JSON.stringify(result));
 const percent=Number(result.coverage.match(/(\d+)%/)?.[1]||NaN);
 assert.ok(percent>0&&percent<50,'Obvious organizational/filler sections were not excluded: '+JSON.stringify(result));
 assert.ok(result.kept.length>=3,'All 3 teaching explanations should remain: '+JSON.stringify(result));
 assert.ok(!result.kept.some(x=>x.left>=20&&x.left<=40),'Organizational mic break was selected');
 assert.ok(result.kept.some(x=>x.left>85),'Late educational explanation incorrectly dropped');
 await page.screenshot({path:'mvp-sparse-lecture-timeline.png',fullPage:false});
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 assert.ok(await page.locator('#story-piece-list').isVisible());
 assert.deepEqual(errors,[]);
 console.log('FULL_CONTENT_SPARSE_LECTURE_SUCCESS',JSON.stringify({coveragePercent:percent,
  selectedSourcePieces:result.kept.length,grayGaps:result.skipped,clips:result.clipCount}));
}finally{await browser.close()}
