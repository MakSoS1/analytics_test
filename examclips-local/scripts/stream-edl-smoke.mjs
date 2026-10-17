import {chromium} from 'playwright-core';
import {existsSync} from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
const chrome=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
const browser=await chromium.launch({executablePath:chrome,headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({acceptDownloads:true});
 await page.goto('http://127.0.0.1:5173/');
 const [download]=await Promise.all([
  page.waitForEvent('download',{timeout:90000}),
  page.evaluate(async()=>{
   const {openMedia}=await import('/src/media.js');
   const {exportClip}=await import('/src/render.js');
   const input=document.createElement('input');input.type='file';
   // A page navigation can fetch the static test fixture without uploading it
   const blob=await (await fetch('/test-fixture.mp4')).blob();
   const file=new File([blob],'test-fixture.mp4',{type:'video/mp4'});
   const media=await openMedia(file),writes=[];
   const writable=new WritableStream({
    write(chunk){
     writes.push({position:chunk.position,data:new Uint8Array(chunk.data)});
    }
   });
   try{
    const result=await exportClip(media,{
      start:0,end:3.7,segments:[{start:0,end:1.3},{start:2.2,end:3.7}],
      layout:'hybrid',focusX:50,title:'Long lecture stream path'
    },[],{writable});
    if(result!==null)throw Error('Expected null result from disk streaming');
    const bytes=Math.max(...writes.map(x=>x.position+x.data.byteLength));
    if(bytes<5000)throw Error('Stream output empty');
    const assembled=new Uint8Array(bytes);
    for(const entry of writes)assembled.set(entry.data,entry.position);
    const href=URL.createObjectURL(new Blob([assembled],{type:'video/mp4'}));
    const a=document.createElement('a');a.href=href;a.download='stream-edl-test.mp4';
    document.body.append(a);a.click();a.remove();
   }finally{await media.input.dispose()}
  })
 ]);
 await download.saveAs('stream-edl-test.mp4');
 const result=JSON.parse(execFileSync('ffprobe',['-v','error','-show_entries','format=duration,size:stream=codec_type,codec_name','-of','json','stream-edl-test.mp4'],{encoding:'utf8'}));
 assert.ok(Number(result.format.duration)>2.5&&Number(result.format.duration)<3.1);
 assert.ok(result.streams.some(s=>s.codec_type==='video'&&s.codec_name==='h264'));
 assert.ok(result.streams.some(s=>s.codec_type==='audio'&&s.codec_name==='aac'));
 execFileSync('ffmpeg',['-v','error','-i','stream-edl-test.mp4','-f','null','-']);
 console.log('DISK_STREAM_EDL_SUCCESS',result.format.duration,result.format.size);
}finally{await browser.close()}
