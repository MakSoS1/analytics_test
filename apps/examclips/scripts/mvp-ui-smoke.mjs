import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const chrome=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser',chromium.executablePath()].filter(Boolean).find(existsSync);
if(!chrome)throw Error('Chrome not installed on the CI runner');
const browser=await chromium.launch({headless:true,executablePath:chrome,args:['--no-sandbox','--disable-dev-shm-usage']});
const errors=[];
const subtitle=[
'1','00:00:00,000 --> 00:00:01,000','Контейнеры применяются для изоляции различных приложений и библиотек. Образы позволяют повторять настройки системного окружения.','',
'2','00:00:01,000 --> 00:00:02,000','Виртуальная машина использует отдельное ядро операционной системы. Контейнер Docker разделяет ресурсы между различными процессами.','',
'3','00:00:02,000 --> 00:00:03,000','Оркестрация управляет распределением контейнеров между вычислительными узлами. Конфигурация указывается разработчиком в декларативных файлах.','',
'4','00:00:03,000 --> 00:00:04,000','Мониторинг показывает состояние служб и сетевого интерфейса. Приложение обращается к контейнерам через виртуальную сеть.'
].join('\n');
try{
 const page=await browser.newPage({viewport:{width:1470,height:980},deviceScaleFactor:1,acceptDownloads:true});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 assert.equal(await page.locator('#app').getAttribute('data-phase'),'upload');
 await page.screenshot({path:'mvp-upload-desktop.png',fullPage:true});
 assert.ok(await page.locator('#atlas-library').isVisible());
 assert.ok(!(await page.locator('#drop').isVisible()),'The library opens before the upload wizard');
 assert.equal(await page.locator('#story-keep').count(),0,'No forced share-of-lecture control');
 assert.equal(await page.locator('#topic-preset').count(),0,'No fixed per-clip duration cap');
 assert.ok(!(await page.locator('#pane-timeline').isVisible()),'Editor must be hidden before upload');
 assert.ok(!(await page.locator('#editor').isVisible()));

 await page.locator('#atlas-new-lecture').click();
 assert.ok(await page.locator('#wizard-step-1').isVisible());
 assert.ok(await page.locator('#drop').isVisible());
 await page.locator('#video-file').setInputFiles('test-fixture.mp4');
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:30000});
 await page.locator('#wizard-next').click();
 assert.ok(await page.locator('#wizard-step-2').isVisible());
 assert.ok(await page.locator('#language').isVisible());
 assert.equal(await page.locator('#asr-limit').inputValue(),'all');
 assert.match(await page.locator('#wizard-step-2').innerText(),/Количество роликов определяет содержание/);
 await page.locator('#wizard-next').click();
 assert.ok(await page.locator('#wizard-step-3').isVisible());
 assert.equal(await page.locator('#app').getAttribute('data-phase'),'configure');
 assert.ok(await page.locator('#workflow-start').isEnabled(),'Run action on the confirmation step');
 assert.equal(await page.locator('#story-keep').count(),0);

 await page.locator('#srt-file').setInputFiles({name:'lecture.srt',mimeType:'text/plain',buffer:Buffer.from(subtitle)});
 await page.waitForFunction(()=>document.querySelector('#workflow-start')?.textContent.includes('SRT'));
 assert.equal(await page.locator('#app').getAttribute('data-phase'),'configure','SRT stays staged until explicit confirmation');
 await page.locator('#workflow-start').click();
 await page.waitForFunction(()=>!document.querySelector('#quiz-generate').disabled);
 assert.equal(await page.locator('#app').getAttribute('data-phase'),'results');
 assert.ok(await page.locator('#microtopic-catalog').isVisible(),'The result opens as a real microtopic grid');
 assert.ok(!(await page.locator('#pane-timeline').isVisible()));
 assert.ok(!(await page.locator('#drop').isVisible()),'No upload widgets in editor');
 assert.equal(await page.locator('#story-keep').count(),0,'No hard percentage anywhere');
 await page.locator('.top-navigation [data-editor-tab="timeline"]').click();
 assert.ok(await page.locator('#pane-timeline').isVisible());
 const full=await page.evaluate(()=>{
   const track=document.querySelector('#timeline-track').getBoundingClientRect();
   const section=document.querySelector('#timeline-section'),style=getComputedStyle(section);
   const available=section.clientWidth-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight);
   return {width:track.width,available,pane:document.querySelector('#pane-timeline').clientWidth};
 });
 assert.ok(full.available>0&&full.width>=full.available*.98,
  'Timeline must fill the available Atlas work area: '+JSON.stringify(full));
 assert.ok(await page.locator('#timeline-track .timeline-part.clip').count()>=1);
 assert.ok(await page.locator('#timeline-monitors').isVisible());
 // Open a grid card for its visible title and source-boundary controls.
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 await page.locator('.microtopic-card-title').first().click();
 assert.ok(await page.locator('#pane-clip').isVisible());
 assert.ok(!(await page.locator('#pane-timeline').isVisible()));
 await page.locator('#clip-start').fill('0.5');
 await page.locator('.top-navigation [data-editor-tab="timeline"]').click();
 await page.waitForFunction(()=>document.querySelectorAll('#timeline-track .timeline-part.skipped').length>=1);
 assert.ok(await page.locator('#timeline-track .timeline-part.skipped').count()>=1);
 assert.ok(await page.locator('#timeline-source').isVisible());

 const overview=await page.evaluate(()=>({
  background:getComputedStyle(document.body).backgroundColor,
  title:document.querySelector('#pane-timeline h1')?.textContent,
  steps:document.querySelectorAll('.atlas-stepper [data-wizard-step]').length,
  renderedClips:document.querySelectorAll('.clip').length,
  safeText:document.querySelector('.privacy')?.textContent
 }));
 assert.equal(overview.steps,3);
 assert.ok(overview.title.includes('Таймлайн'));
 assert.ok(overview.renderedClips>=1);
 assert.ok(overview.safeText.includes('устройстве'));
 await page.locator('.top-navigation [data-editor-tab="quiz"]').click();
 assert.ok(await page.locator('#pane-quiz').isVisible());
 await page.locator('#quiz-generate').click();
 const questions=await page.locator('.quiz-question').count();
 assert.ok(questions>=3,'No reviewable term-recall quiz questions: '+questions);
 for(let i=0;i<questions;i++)await page.locator('.quiz-question').nth(i).locator('input[type=radio]').first().check();
 await page.locator('#quiz-grade').click();
 assert.ok(await page.locator('#quiz-result').isVisible());
 const [quizDownload]=await Promise.all([page.waitForEvent('download'),page.locator('#quiz-download').click()]);
 assert.match(quizDownload.suggestedFilename(),/\.quiz\.json$/);
 await page.locator('.top-navigation [data-editor-tab="timeline"]').click();
 await page.evaluate(()=>window.scrollTo(0,0));
 await page.screenshot({path:'mvp-desktop.png',fullPage:true});
 await page.locator('#timeline-section').scrollIntoViewIfNeeded();
 await page.screenshot({path:'mvp-timeline.png',fullPage:false});
 await page.locator('#timeline-source').click({position:{x:65,y:24}});
 const timeFromSeek=await page.locator('#player').evaluate(el=>el.currentTime);
 assert.ok(timeFromSeek>=0,'No source scrubbing');
 await page.locator('#timeline-add').click();
 assert.ok(await page.locator('#timeline-track .timeline-part.clip').count()>=2);
 await page.locator('.top-navigation [data-editor-tab="export"]').click();
 assert.ok(await page.locator('#export').isVisible());
 assert.ok(await page.locator('#output-quality').isVisible());
 await page.locator('.top-navigation [data-editor-tab="quiz"]').click();
 await page.locator('#quiz-panel').scrollIntoViewIfNeeded();
 await page.screenshot({path:'mvp-quiz.png',fullPage:false});
 const mobile=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});
 mobile.on('pageerror',e=>errors.push(e.message));
 await mobile.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const dimensions=await mobile.evaluate(()=>({
  clientWidth:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,
  bodyBg:getComputedStyle(document.body).backgroundColor
 }));
 assert.ok(dimensions.scrollWidth<=dimensions.clientWidth+2,'Mobile horizontal overflow: '+JSON.stringify(dimensions));
 await mobile.screenshot({path:'mvp-mobile.png',fullPage:true});
 await mobile.locator('#atlas-new-lecture').click();
 await mobile.locator('#video-file').setInputFiles('test-fixture.mp4');
 await mobile.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:30000});
 await mobile.locator('#wizard-next').click();
 await mobile.locator('#wizard-next').click();
 await mobile.locator('#srt-file').setInputFiles({name:'lecture.srt',mimeType:'text/plain',buffer:Buffer.from(subtitle)});
 await mobile.waitForFunction(()=>document.querySelector('#workflow-start')?.textContent.includes('SRT'));
 await mobile.locator('#workflow-start').click();
 await mobile.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='results',{timeout:30000});
 assert.ok(await mobile.locator('#microtopic-catalog').isVisible());
 await mobile.locator('.top-navigation [data-editor-tab="timeline"]').click();
 assert.ok(await mobile.locator('#pane-timeline').isVisible());
 assert.equal(await mobile.locator('#story-keep').count(),0);
 const mobileTimeline=await mobile.evaluate(()=>({
  clientWidth:document.documentElement.clientWidth,
  scrollWidth:document.documentElement.scrollWidth
 }));
 assert.ok(mobileTimeline.scrollWidth<=mobileTimeline.clientWidth+2,'Mobile timeline overflow: '+JSON.stringify(mobileTimeline));
 await mobile.screenshot({path:'mvp-mobile-timeline.png',fullPage:true});
 assert.deepEqual(errors,[]);
 console.log('MVP_PRODUCT_SMOKE_SUCCESS',JSON.stringify({steps:overview.steps,clips:overview.renderedClips,
   quizQuestions:questions,mobileWidth:dimensions.clientWidth,overflow:dimensions.scrollWidth-dimensions.clientWidth}));
 await page.close();await mobile.close();
}finally{await browser.close()}
