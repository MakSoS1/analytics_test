/** Local acceptance runner using the SAME planner/composer/exporter as the app.
 * Requires running Vite, Chrome, ffmpeg and tesseract. No media leaves localhost.
 * node scripts/render-real-lecture.mjs VIDEO TRANSCRIPT_JSON OUT [1,2,3|all]
 */
import {chromium} from 'playwright-core';
import {mkdir,readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);
const [video,transcript,output,selection='1']=process.argv.slice(2);
if(!video||!transcript||!output)throw Error('Expected VIDEO TRANSCRIPT_JSON OUTPUT [indices|all]');
await mkdir(output,{recursive:true});
const temp=await mkdtemp(join(tmpdir(),'examclips-ocr-'));
const rows=JSON.parse(await readFile(transcript,'utf8')).rows;
const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,args:['--no-sandbox']});
const page=await browser.newPage({acceptDownloads:true});
const started=performance.now();
const errors=[];page.on('pageerror',e=>errors.push(e.message));
// Freeze this acceptance run while implementation files are edited.
await page.route('**/@vite/client',route=>route.fulfill({body:`export class ErrorOverlay{};export const createHotContext=()=>({data:{},accept(){},dispose(){},prune(){},on(){},off(){},send(){},invalidate(){}});export const injectQuery=url=>url;export function updateStyle(id,content){let el=document.getElementById(id);if(!el){el=document.createElement('style');el.id=id;document.head.append(el)}el.textContent=content}export function removeStyle(id){document.getElementById(id)?.remove()}`,contentType:'application/javascript'}));
await page.route('**/acceptance-source.mp4',route=>route.fulfill({path:resolve(video),contentType:'video/mp4'}));
await page.exposeFunction('nativeOcr',async(base64)=>{
 const file=join(temp,'frame.png');await writeFile(file,Buffer.from(base64,'base64'));
 const {stdout}=await exec('tesseract',[file,'stdout','-l','eng','--psm','11','tsv'],{maxBuffer:8e6});
 const grouped=new Map();
 for(const row of stdout.trim().split('\n').slice(1)){
  const c=row.split('\t');if(c[0]!=='5'||!c[11]?.trim()||+c[10]<35)continue;
  const id=c.slice(1,5).join('-'),x=+c[6],y=+c[7],w=+c[8],h=+c[9];
  const g=grouped.get(id)||{text:'',confidence:100,box:{x0:x,y0:y,x1:x+w,y1:y+h}};
  g.text+=(g.text?' ':'')+c.slice(11).join('\t');g.confidence=Math.min(g.confidence,+c[10]);
  g.box.x0=Math.min(g.box.x0,x);g.box.y0=Math.min(g.box.y0,y);g.box.x1=Math.max(g.box.x1,x+w);g.box.y1=Math.max(g.box.y1,y+h);grouped.set(id,g);
 }
 return [...grouped.values()];
});
try{
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'domcontentloaded'});
 const plan=await page.evaluate(async({rows,name})=>{
  const {openMedia}=await import('/src/media.js');
  const {planGeneralTopics:planCompleteTopics}=await import('/src/general-topics.js');
  const {buildVerifiedLessonScreenplays}=await import('/src/lesson-screenplay.js');
  const file=new File([await(await fetch('/acceptance-source.mp4')).blob()],name,{type:'video/mp4'});
  window.auditMedia=await openMedia(file);window.auditRows=rows;
  const meta={...auditMedia,name};
  const {indexLectureSlides}=await import('/src/slide-chapter-index.js');
  const structure=await indexLectureSlides(auditMedia,{recognize:async canvas=>({lines:await window.nativeOcr(canvas.toDataURL('image/png').split(',')[1])})});
  const planned=planCompleteTopics(rows,meta.duration,{chapters:structure.chapters,sceneCuts:structure.cuts});
  window.auditClips=buildVerifiedLessonScreenplays(planned.clips,rows);
  return {...planned,clips:auditClips};
 },{rows,name:video.split('/').at(-1)});
 await writeFile(join(output,'render-plan.json'),JSON.stringify(plan,null,2));
 const indices=selection==='plan'?[]:selection==='all'?plan.clips.map((_,i)=>i):selection.split(',').map(n=>Number(n)-1);
 const results=[];
 for(const index of indices){
  if(!plan.clips[index])throw Error('Unknown clip '+(index+1));
  const start=performance.now();
  console.log('RENDER_START',index+1,plan.clips[index].title);
  const scenes=await page.evaluate(async(index)=>{
   const {sampleSlideCuts}=await import('/src/slide-cuts.js');
   const {makeStoryboard}=await import('/src/scene-model.js');
   const {sourceSegments}=await import('/src/selective-stories.js');
   const clip=auditClips[index];clip.scenes=[];
   for(const piece of sourceSegments(clip)){
    const cuts=await sampleSlideCuts(auditMedia,piece);const chapters=[];
    for(let i=0;i<cuts.length;i++){
     const offset=cuts[i],until=cuts[i+1]??piece.end-piece.start;
     const frame=await auditMedia.videoSink.getSample(piece.start+offset+Math.min(12,(until-offset)*.6));
     const canvas=document.createElement('canvas');canvas.width=auditMedia.width;canvas.height=auditMedia.height;
     const ctx=canvas.getContext('2d',{willReadFrequently:true});try{frame.draw(ctx,0,0,canvas.width,canvas.height)}finally{frame.close()}
     const lines=await window.nativeOcr(canvas.toDataURL('image/png').split(',')[1]);
     const scoped=auditRows.filter(r=>r.end>piece.start+offset&&r.start<piece.start+until).map(r=>({...r,start:r.start-piece.start-offset,end:r.end-piece.start-offset}));
     const scene=makeStoryboard({width:canvas.width,height:canvas.height,lines,pixels:ctx.getImageData(0,0,canvas.width,canvas.height).data,
      duration:until-offset,chunks:scoped,titleOverride:clip.title,speaker:{x:.845,y:.843,w:.15,h:.15}});
     chapters.push({start:offset,end:until,scene});
    }
    clip.scenes.push({...chapters[0].scene,chapters});
   }
   return clip.scenes;
  },index);
  const sceneSeconds=(performance.now()-start)/1000;
  await writeFile(join(output,`clip-${index+1}-scenes.json`),JSON.stringify(scenes,null,2));
  const download=page.waitForEvent('download',{timeout:3600000});
  download.catch(()=>{});
  const render=await page.evaluate(async(index)=>{
   const {exportClip}=await import('/src/render.js');
   const began=performance.now();
   const blob=await exportClip(auditMedia,auditClips[index],auditRows);
   const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`clip-${index+1}.mp4`;a.click();
   return {renderSeconds:(performance.now()-began)/1000,bytes:blob.size};
  },index);
  await(await download).saveAs(join(output,`clip-${index+1}.mp4`));
  const item={index:index+1,title:plan.clips[index].title,seconds:plan.clips[index].outputSeconds,sceneSeconds,...render};results.push(item);
  console.log('RENDER_COMPLETE',JSON.stringify(item));
  await writeFile(join(output,'render-metadata.json'),JSON.stringify({elapsedSeconds:(performance.now()-started)/1000,results,errors},null,2));
 }
 const project=await page.evaluate(()=>({schema:2,videoName:'HAHL2026_Lecture01_Docker.mp4',duration:auditMedia.duration,
  clips:auditClips,chunks:auditRows,selected:0,activeTab:'clip',ui:{detailOpen:false},
  settings:{language:'en',asrModel:'base',asrLimit:'all',ocrEngine:'auto',outputQuality:'standard'}}));
 project.videoName=video.split('/').at(-1);
 await writeFile(join(output,'lecture-project.json'),JSON.stringify(project,null,2));
}finally{await browser.close();await rm(temp,{recursive:true,force:true})}
