import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox']});
const text=(i)=>i===0
 ? 'Сейчас разберём практическую задачу по математике: вычислим производную функции по определению.'
 : i===80
   ? 'Таким образом задача решена. Проверим найденный ответ и сделаем окончательный вывод.'
   : 'Шаг номер '+i+'. Подставляем значения в формулу, вычисляем производную и проверяем каждое преобразование. Это необходимо, чтобы получить правильное решение.';
const timestamp=t=>{
 const h=Math.floor(t/3600),m=Math.floor(t/60)%60,s=Math.floor(t)%60;
 return [h,m,s].map(v=>String(v).padStart(2,'0')).join(':')+',000';
};
const rows=Array.from({length:81},(_,i)=>[
 String(i+1),timestamp(i*15)+' --> '+timestamp((i+1)*15),text(i),''
].join('\n'));
rows.push(['82',timestamp(1220)+' --> '+timestamp(1240),
'Теперь перейдём к другой теме: рассмотрим алгоритм кратчайшего пути на графе.',''].join('\n'));
const srt=rows.join('\n');
try{
 const page=await browser.newPage({viewport:{width:1440,height:900}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:5173/');
 await page.locator('#video-file').setInputFiles('long-exercise-fixture.mp4');
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:60000});
 await page.locator('#srt-file').setInputFiles({name:'worked-20-minutes.srt',mimeType:'text/plain',buffer:Buffer.from(srt)});
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results',{timeout:45000});
 const check=await page.evaluate(()=>{
  const caption=document.querySelector('#selected-time').textContent;
  const count=Number(document.querySelector('#clip-count').textContent);
  const start=document.querySelector('#clip-start').value;
  const end=document.querySelector('#clip-end').value;
  const path=document.querySelector('#timeline-coverage').textContent;
  return {caption,count,start,end,path};
 });
 assert.equal(check.count,1,'A 20s topic announcement without an explanation must not become a standalone short: '+JSON.stringify(check));
 assert.ok(Number(check.end)-Number(check.start)>=1200,'20 minute worked problem was wrongly chopped '+JSON.stringify(check));
 assert.ok(check.caption.includes('00:20'),'Expected 20+min timecode '+JSON.stringify(check));
 assert.equal(await page.locator('#story-keep').count(),0);
 assert.equal(await page.locator('#topic-preset').count(),0);
 await page.screenshot({path:'mvp-20minute-problem-timeline.png',fullPage:false});
 assert.deepEqual(errors,[]);
 console.log('LONG_WORKED_EXERCISE_UI_SUCCESS',JSON.stringify(check));
}finally{await browser.close()}
