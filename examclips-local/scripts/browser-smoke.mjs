import {chromium} from 'playwright-core';
import {execFileSync} from 'node:child_process';
import {existsSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';

const cwd=process.cwd(),fixture=resolve(cwd,'test-fixture.mp4'),srt=resolve(cwd,'test-fixture.srt');
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('No preinstalled browser; install Chrome on runner.');
const browser=await chromium.launch({headless:true,executablePath:chrome,args:['--no-sandbox','--disable-dev-shm-usage']});
const page=await browser.newPage({acceptDownloads:true,viewport:{width:1450,height:950}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
try{
  await page.goto('http://127.0.0.1:5173/',{waitUntil:'networkidle',timeout:30000});
  await page.locator('#video-file').setInputFiles(fixture);
  await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:30000});
  const fileNote=await page.locator('#file-note').innerText();assert.match(fileNote,/test-fixture\.mp4/);
  await page.locator('#srt-file').setInputFiles(srt);
  await page.waitForFunction(()=>!document.querySelector('#export').disabled,{timeout:30000});
  const count=await page.locator('#clip-count').innerText();assert.equal(count,'1');
  const title=await page.locator('#clip-title').inputValue();assert.ok(title.length>0);
  await page.locator('#layout').selectOption('fit');
  await page.screenshot({path:resolve(cwd,'smoke-ui.png'),fullPage:true});
  const support=await page.evaluate(()=>typeof VideoEncoder!=='undefined'&&typeof AudioEncoder!=='undefined');
  if(support){
    try{
      const [download]=await Promise.all([page.waitForEvent('download',{timeout:120000}),page.locator('#export').click()]);
      const destination=resolve(cwd,'smoke-output.mp4');
      await download.saveAs(destination);
      const info=JSON.parse(execFileSync('ffprobe',['-v','error','-show_entries','format=duration,size:stream=codec_type,codec_name,width,height','-of','json',destination],{encoding:'utf-8'}));
      assert.ok(info.format.duration>2&&info.format.duration<5);
      assert.ok(info.streams.some(s=>s.codec_type==='video'&&s.width===720&&s.height===1280));
      assert.ok(info.streams.some(s=>s.codec_type==='audio'));
      console.log('MP4_SMOKE_SUCCESS',info.format.duration,info.format.size);
    }catch(err){
      console.error('MP4_SMOKE_FAILURE',err.message,await page.locator('#progress').innerText());
      throw err;
    }
  }else{
    console.log('ENCODERS_NOT_SUPPORTED: verified graceful error path');
    await page.locator('#export').click();
    await page.waitForTimeout(1000);
    assert.match(await page.locator('#progress').innerText(),/WebCodecs Encoder недоступен/);
  }
  assert.deepEqual(errors,[]);
  console.log('BROWSER_SMOKE_SUCCESS');
}finally{await browser.close()}
