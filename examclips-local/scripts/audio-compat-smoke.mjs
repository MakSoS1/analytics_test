import {chromium} from 'playwright-core';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,args:['--no-sandbox']});
const fixture=resolve(process.env.MEDIA_FIXTURE||'test-fixture.mp4');
const info=JSON.parse(execFileSync('ffprobe',['-v','error','-show_format','-of','json',fixture]));
const start=Number(info.format.duration)>130?120:0;
const referenceBytes=execFileSync('ffmpeg',['-loglevel','error','-ss',String(start),'-i',fixture,'-t','2','-f','f32le','-ac','1','-ar','16000','pipe:1']);
const reference=Array.from(new Float32Array(referenceBytes.buffer,referenceBytes.byteOffset,referenceBytes.byteLength/4));
try{
 const page=await browser.newPage();
 await page.route('**/audio-compat-source.mp4',r=>r.fulfill({path:fixture,contentType:'video/mp4'}));
 // Reproduce YaBrowser: capability query says yes, configure rejects AAC.
 if(!process.env.REAL_DECODER)await page.addInitScript(()=>{const Native=AudioDecoder;window.AudioDecoder=class extends Native{configure(c){if(c.codec.startsWith('mp4a'))throw new DOMException('Unsupported configuration','OperationError');return super.configure(c)}}});
 await page.goto(process.env.EXAMCLIPS_ORIGIN||'http://127.0.0.1:5173/');
 const result=await page.evaluate(async(reference)=>{
  const {openMedia,mono16k}=await import('/src/media.js');
  const media=await openMedia(new File([await(await fetch('/audio-compat-source.mp4')).blob()],'lecture.mp4'));
  try{
   const start=media.duration>130?120:0;
   const pcm=await mono16k(media.audioSink,start,start+Math.min(2,media.duration));
   const energy=pcm.reduce((n,v)=>n+v*v,0)/pcm.length;
   let dot=0,xx=0,yy=0;for(let i=1000;i<pcm.length-1000;i++){const x=pcm[i],y=reference[i];dot+=x*y;xx+=x*x;yy+=y*y}
   const correlation=dot/Math.sqrt(xx*yy);
   const {exportClip}=await import('/src/render.js');
   const clip={title:'Compatibility',layout:'hybrid',start,end:start+Math.min(3,media.duration),scene:{hideSpeaker:true},focusX:50};
   const blob=await exportClip(media,clip,[]);
   const audioSamples=[];for await(const item of media.audioSampleSink.samples(start,start+2)){audioSamples.push({time:item.timestamp,duration:item.duration});item.close()}
   return {mode:media.audioDecoding,samples:pcm.length,energy,correlation,bytes:blob.size,audioSamples};
  }finally{await media.input.dispose()}
 },reference);
 if(!process.env.REAL_DECODER)assert.equal(result.mode,'webaudio');
 assert.ok(result.correlation>.99,'Audio must match the original at the same timestamps, without decoder priming shift');
 assert.equal(result.samples,32000);assert.ok(result.energy>1e-7,'Decoded source audio must be non-silent');assert.ok(result.bytes>1000);assert.ok(result.audioSamples.length>0);
 assert.ok(Math.abs(result.audioSamples[0].time-start)<.05);
 console.log('AUDIO_COMPAT_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
