import {chromium} from 'playwright-core';
import {execFileSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!chrome)throw Error('No Chrome');
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox']});
const page=await browser.newPage({acceptDownloads:true,viewport:{width:1280,height:850}});
try{
 await page.goto('http://127.0.0.1:5173/');
 await page.locator('#video-file').setInputFiles('test-fixture.mp4');
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled,{timeout:25000});
 await page.locator('#srt-file').setInputFiles('test-fixture.srt');
 await page.waitForFunction(()=>document.querySelector('#app').dataset.phase==='results');
 const [download]=await Promise.all([
   page.waitForEvent('download',{timeout:120000}),
   page.evaluate(async()=>{
     const file=document.querySelector('#video-file').files[0];
     const {openMedia}=await import('/src/media.js');
     const {exportClip}=await import('/src/render.js');
     const media=await openMedia(file);
     const segments=[{start:0,end:1.3},{start:2.2,end:3.7}];
     const clip={start:0,end:3.7,segments,title:'Nonlinear Docker example',layout:'hybrid',focusX:50,
       status:'needs-review'};
     try{
       const blob=await exportClip(media,clip,[
         {start:0,end:1.3,text:'Docker parts one'},
         {start:2.2,end:3.7,text:'And after missing section part two'}
       ]);
       const a=document.createElement('a'),url=URL.createObjectURL(blob);
       a.href=url;a.download='nonconsecutive-source-test.mp4';document.body.append(a);a.click();a.remove();
       setTimeout(()=>URL.revokeObjectURL(url),60000);
     }finally{await media.input.dispose()}
   })
 ]);
 const path='nonconsecutive-source-test.mp4';await download.saveAs(path);
 const meta=JSON.parse(execFileSync('ffprobe',['-v','error','-show_entries',
   'format=duration,size:stream=codec_type,codec_name,width,height','-of','json',path],{encoding:'utf8'}));
 const seconds=Number(meta.format.duration);
 assert.ok(seconds>=2.60&&seconds<3.1,'Source video gap was not removed: '+seconds);
 assert.ok(meta.streams.some(x=>x.codec_type==='video'&&x.width===720&&x.height===1280));
 assert.ok(meta.streams.some(x=>x.codec_type==='audio'&&x.codec_name==='aac'));
 execFileSync('ffmpeg',['-v','error','-i',path,'-f','null','-'],{stdio:'pipe'});
 console.log('NONCONTIGUOUS_EDL_MP4_SUCCESS',JSON.stringify({duration:seconds,bytes:Number(meta.format.size),segments:2,audio:true}));
}finally{await browser.close()}
