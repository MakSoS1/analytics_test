import {chromium} from 'playwright-core';
import {existsSync,readFileSync,mkdirSync} from 'node:fs';
import assert from 'node:assert/strict';

const executablePath=[process.env.CHROME_PATH,'/usr/bin/google-chrome','/usr/bin/chromium',chromium.executablePath()].filter(Boolean).find(existsSync);
const browser=await chromium.launch({executablePath,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
const origin=process.env.EXAMCLIPS_ORIGIN||'http://127.0.0.1:5173/';
mkdirSync('test-results',{recursive:true});
const original={id:'edited-edl',title:'Мой проверенный монтаж',start:0,end:160,
 segments:[{start:150,end:160},{start:0,end:30}],layout:'hybrid',focusX:50,status:'approved',approvedAt:'2026-10-19T08:00:00Z'};
const data={schema:2,videoName:'Сохранённая Docker лекция.mp4',duration:180,clips:[original],
 chunks:[
  {start:60,end:85,text:'Контейнер представляет собой изолированную среду для приложения и его зависимостей, поэтому запуск остаётся воспроизводимым.'},
  {start:86,end:120,text:'Например приложение запускается из одного образа на разных серверах. Таким образом зависимости и настройки сохраняются при переносе.'}
 ],sceneCuts:[],lectureChapters:[],selected:0,activeTab:'clip',view:{zoom:8,offset:.1},
 settings:{language:'ru',asrModel:'base',asrLimit:'all',ocrEngine:'auto',outputQuality:'high'},ui:{detailOpen:false,catalogScroll:0}};
const errors=[];
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000},acceptDownloads:true});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(origin);
 await page.locator('#project-file').setInputFiles({name:'saved-project.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(data))});
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results');
 assert.ok(await page.locator('#atlas-source-missing').isVisible());
 assert.equal(await page.locator('#atlas-stat-clips').textContent(),'1');
 assert.equal(await page.locator('#atlas-stat-coverage').textContent(),'22%','Union of real EDL intervals, not the 160-second envelope');
 assert.equal(await page.locator('#atlas-stat-ready').textContent(),'1/1');
 await page.locator('#atlas-select-range').click();
 async function range(start,end){
  await page.locator('#atlas-range-end').fill(String(end));await page.locator('#atlas-range-end').press('Tab');
  await page.locator('#atlas-range-start').fill(String(start));await page.locator('#atlas-range-start').press('Tab');
 }
 await range(55,125);
 await page.locator('#atlas-range-find').click();
 assert.equal(await page.locator('.microtopic-card').count(),2);
 assert.equal(await page.locator('#atlas-stat-clips').textContent(),'1','Candidates do not inflate the accepted series');
 assert.equal(await page.locator('#atlas-stat-coverage').textContent(),'22%');
 await page.locator('#atlas-range-find').click();
 assert.equal(await page.locator('.microtopic-card').count(),2,'Repeated search must not duplicate candidates');
 await page.locator('.top-navigation [data-editor-tab="export"]').click();
 async function snapshot(name){
  const waiting=page.waitForEvent('download');await page.locator('#save-project').click();
  const download=await waiting;const path='test-results/'+name;await download.saveAs(path);
  return JSON.parse(readFileSync(path,'utf8'));
 }
 const searched=await snapshot('atlas-searched.project.json');
 assert.deepEqual(searched.clips[0],original,'Range search must preserve edited title, approval, source order and intervals exactly');
 assert.equal(searched.clips[1].candidate,true);
 assert.equal(searched.clips[1].start,60);assert.equal(searched.clips[1].end,120);
 assert.equal(searched.settings.language,'ru');assert.equal(searched.settings.asrModel,'base');
 assert.equal(searched.settings.outputQuality,'high');
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 await page.locator('.microtopic-card[data-topic-index="1"]').click();
 assert.ok(await page.locator('#atlas-accept-current').isVisible());
 assert.ok(await page.locator('#atlas-export-clip').isDisabled());
 await page.locator('#atlas-accept-current').click();
 await page.locator('#microtopic-back').click();
 assert.equal(await page.locator('#atlas-stat-clips').textContent(),'2');
 assert.equal(await page.locator('#atlas-stat-coverage').textContent(),'56%');
 await range(130,142);await page.locator('#atlas-range-create').click();
 assert.ok(await page.locator('#microtopic-detail').isVisible());
 assert.equal(await page.locator('#clip-start').inputValue(),'130.0');
 assert.equal(await page.locator('#clip-end').inputValue(),'142.0');
 await page.locator('#clip-title').fill('Ручной участок без потери старого монтажа');
 await page.locator('#back-to-library').click();
 await page.waitForFunction(()=>!document.querySelector('#atlas-library').hidden);
 assert.equal(await page.locator('.library-item').count(),1);
 await page.locator('.library-item-actions button').first().click();
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results');
 assert.ok(await page.locator('#microtopic-detail').isVisible());
 assert.equal(await page.locator('#clip-title').inputValue(),'Ручной участок без потери старого монтажа');
 await page.locator('#video-file').setInputFiles('test-fixture.mp4');
 assert.match(await page.locator('#progress').textContent(),/другой исходник/);
 assert.equal(await page.locator('#clip-title').inputValue(),'Ручной участок без потери старого монтажа');
 await page.locator('.top-navigation [data-editor-tab="export"]').click();
 const saved=await snapshot('atlas-preserved.project.json');
 assert.deepEqual(saved.clips[0],original);
 assert.equal(saved.clips.length,3);
 assert.equal(saved.clips[1].candidate,false);
 assert.equal(saved.clips[2].candidate,false);
 assert.deepEqual(saved.clips[2].segments,[{start:130,end:142}]);
 await page.locator('#project-file').setInputFiles({name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('{"schema":99}')});
 await page.waitForFunction(()=>document.querySelector('#progress').textContent.includes('Неизвестный формат'));
 assert.match(await page.locator('#progress').textContent(),/Неизвестный формат/);
 const afterInvalid=await snapshot('atlas-after-invalid.project.json');
 assert.deepEqual(afterInvalid.clips,saved.clips,'A rejected JSON import must leave the existing project intact');
 assert.deepEqual(errors,[]);
 console.log('ATLAS_PROJECT_FLOWS_SUCCESS: metadata-only import, real EDL coverage, non-destructive range discovery, no duplicates, candidate acceptance, manual range, settings JSON, source mismatch and invalid JSON preserve edits');
}finally{await browser.close()}
