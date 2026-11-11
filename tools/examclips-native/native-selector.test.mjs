import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {chromium} from 'playwright';

// This isolated synthetic DOM checks UI routing only. It does not mock or call
// File System Access, app state, ASR, media encoding, or the native picker.
const source=await readFile(new URL('./run.mjs',import.meta.url),'utf8');
const start=source.indexOf('async function selectClip(index){');
const end=source.indexOf('\nasync function capabilities()',start);
assert.ok(start>=0&&end>start,'actual harness selection function must be found');
const selectionSource=source.slice(start,end);
const trigger=source.split('\n').find(line=>/click\(\{timeout:15000\}\);await dialogPromise/.test(line));
assert.ok(trigger,'actual harness export action must be found');
let browser;
before(async()=>{browser=await chromium.launch({channel:'chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});});
after(async()=>{await browser?.close();});
async function fixture(){
 const page=await browser.newPage();
 await page.setContent('<div class="top-navigation"><button data-editor-tab="clip">Clips</button></div>'+
  '<article class="microtopic-card" data-topic-index="1"><button class="microtopic-card-title">Topic two</button></article>'+
  '<button id="export" hidden>Legacy export</button><button id="atlas-export-clip" hidden>Visible export</button>'+
  '<p id="state">cards</p>');
 await page.evaluate(()=>{
  window.routeCounts={proxy:0,legacy:0};
  document.querySelector('.microtopic-card-title').addEventListener('click',()=>{
   document.querySelector('#atlas-export-clip').hidden=false;document.querySelector('#state').textContent='detail';
  });
  document.querySelector('#export').addEventListener('click',()=>{window.routeCounts.legacy++;});
  document.querySelector('#atlas-export-clip').addEventListener('click',()=>{
   window.routeCounts.proxy++;document.querySelector('#export').click();
  });
 });
 const select=new Function('page','closeDetail',selectionSource+';return selectClip;')(page,async()=>{});
 return {page,select};
}
test('native harness selects the visible export proxy while the legacy state control stays hidden',async()=>{
 const {page,select}=await fixture();
 try{
  await select(1);
  assert.equal(await page.locator('#state').textContent(),'detail');
  assert.equal(await page.locator('#export').isVisible(),false);
  assert.equal(await page.locator('#export').isEnabled(),true);
  const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
  await new AsyncFunction('page','dialogPromise',trigger)(page,Promise.resolve());
  assert.deepEqual(await page.evaluate(()=>window.routeCounts),{proxy:1,legacy:1});
 }finally{await page.close();}
});
test('native harness still refuses an export disabled by the legacy app state',async()=>{
 const {page,select}=await fixture();
 try{
  await page.evaluate(()=>{document.querySelector('#export').disabled=true;});
  await assert.rejects(()=>select(1),/SELECTED_EXPORT_DISABLED/);
  assert.deepEqual(await page.evaluate(()=>window.routeCounts),{proxy:0,legacy:0});
 }finally{await page.close();}
});
