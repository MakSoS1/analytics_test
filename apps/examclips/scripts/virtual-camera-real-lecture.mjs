/** Local acceptance for the lecture virtual camera with the app's own browser code.
 * Starts Vite in-process, decodes the video in Chrome, indexes the camera and
 * paints vertical frames with paintHybrid. No media leaves localhost.
 * node scripts/virtual-camera-real-lecture.mjs VIDEO OUT_DIR [START END] [t1,t2,...]
 */
import {chromium} from 'playwright-core';
import {createServer} from 'vite';
import {mkdir,writeFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
const [video,output,start='0',end='',list='']=process.argv.slice(2);
if(!video||!output)throw Error('Expected VIDEO OUT_DIR [START END] [times]');
await mkdir(output,{recursive:true});
const executable=[process.env.CHROME_PATH,'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
 '/usr/bin/google-chrome','/usr/bin/chromium',chromium.executablePath()].filter(Boolean).find(existsSync);
const server=await createServer({root:resolve(import.meta.dirname,'..'),server:{port:5179,host:'127.0.0.1',strictPort:true},logLevel:'error'});
await server.listen();
const browser=await chromium.launch({executablePath:executable,headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/acceptance-source.mp4',route=>route.fulfill({path:resolve(video),contentType:'video/mp4'}));
 await page.goto('http://127.0.0.1:5179/',{waitUntil:'domcontentloaded'});
 const result=await page.evaluate(async({name,start,end,list})=>{
  const {openMedia}=await import('/src/media.js');
  const {indexLectureCamera}=await import('/src/lecture-camera.js');
  const {paintFrame}=await import('/src/composition.js');
  const file=new File([await(await fetch('/acceptance-source.mp4')).blob()],name,{type:'video/mp4'});
  const media=await openMedia(file);
  const range={start:Number(start),end:end?Number(end):media.duration};
  const began=performance.now();
  const camera=await indexLectureCamera(media,{ranges:[range]});
  const seconds=(performance.now()-began)/1000;
  const times=list?list.split(',').map(Number):[];
  const frames=[];
  const canvas=document.createElement('canvas');canvas.width=720;canvas.height=1280;
  for(const t of times){
   const sample=await media.videoSink.getSample(t);
   try{
    paintFrame(canvas,sample,sample.displayWidth,sample.displayHeight,'hybrid',50,
     {words:[{text:'Пример',visible:true,active:false},{text:'субтитров',visible:true,active:true}],progress:.5},
     {title:''},t-range.start,t-range.start+5,{camera,sourceTime:t});
   }finally{sample.close()}
   frames.push({t,png:canvas.toDataURL('image/png')});
  }
  return {seconds,duration:range.end-range.start,keys:camera.keys.length,speaker:camera.speaker,webcam:camera.webcam,camera,frames};
 },{name:video.split('/').at(-1),start,end,list});
 for(const f of result.frames)await writeFile(join(output,'frame-'+f.t+'.png'),Buffer.from(f.png.split(',')[1],'base64'));
 await writeFile(join(output,'camera.json'),JSON.stringify(result.camera,null,1));
 console.log(JSON.stringify({seconds:+result.seconds.toFixed(1),duration:result.duration,keys:result.keys,
  speaker:result.speaker,webcam:result.webcam,frames:result.frames.length,errors}));
 if(errors.length)process.exitCode=1;
}finally{await browser.close();await server.close()}
