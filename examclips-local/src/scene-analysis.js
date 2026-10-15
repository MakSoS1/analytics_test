import {flattenOcr,makeStoryboard} from './scene-model.js';
import {motionFromMedia} from './speaker-motion.js';
import {sampleSlideCuts} from './slide-cuts.js';
const createCanvas=(w,h)=>{const canvas=document.createElement('canvas');canvas.width=w;canvas.height=h;return canvas};
let worker=null,language='';
async function ocr(canvas,lang,onProgress){
  const target=lang==='ru'?'rus+eng':'eng';
  if(!worker||language!==target){
    if(worker){await worker.terminate();worker=null}
    const {createWorker}=await import('tesseract.js');
    onProgress('Загрузка локального OCR '+target+' (первый запуск скачивает модели)');
    worker=await createWorker(target,1,{logger:message=>{
      if(message.status==='recognizing text'&&message.progress!==undefined)
        onProgress('Распознавание доски: '+Math.round(message.progress*100)+'%');
    }});language=target;
  }
  const out=await worker.recognize(canvas,{}, {blocks:true});
  return flattenOcr(out.data.blocks||[]);
}
export async function analyzeScene(media,clip,chunks,{language='en',onProgress=()=>{},signal}={}){
  // Lightweight local change detection first. Expensive OCR runs only on distinct slide chapters.
  let cuts=[0],note='',totalLines=0;
  try{cuts=await sampleSlideCuts(media,clip,{signal,onProgress})}
  catch(e){if(e.name==='AbortError')throw e;note='Не удалось определить смены слайдов. '}
  let camera;
  try{camera=await motionFromMedia(media,clip,{signal})}
  catch(e){if(e.name==='AbortError')throw e;camera={found:false,box:{x:.815,y:.854,w:.18,h:.14},confidence:0}}
  const duration=clip.end-clip.start,chapters=[];
  for(let i=0;i<cuts.length;i++){
    if(signal?.aborted)throw new DOMException('Stopped','AbortError');
    const offset=cuts[i],until=cuts[i+1]??duration;
    const at=Math.min(media.duration-.05,clip.start+offset+Math.min(2,(until-offset)/3));
    const sample=await media.videoSink.getSample(Math.max(0,at));
    if(!sample)throw Error('Не удалось получить учебный кадр');
    const canvas=createCanvas(media.width,media.height);
    try{sample.draw(canvas.getContext('2d'),0,0,media.width,media.height)}finally{sample.close()}
    let lines=[];
    try{onProgress('OCR учебной сцены '+(i+1)+'/'+cuts.length);lines=await ocr(canvas,language,onProgress)}
    catch(error){note+='OCR недоступен: '+error.message+'. Исходные рисунки сохранены.'}
    totalLines+=lines.length;
    const scoped=chunks.filter(c=>c.end>clip.start+offset&&c.start<clip.start+until)
      .map(c=>({...c,start:Math.max(0,c.start-clip.start-offset),end:Math.min(until-offset,c.end-clip.start-offset)}));
    const entry=makeStoryboard({width:media.width,height:media.height,speaker:camera.box,lines,
      duration:Math.max(.1,until-offset),chunks:scoped,
      titleOverride:lines.length===0?clip.title:''});
    chapters.push({start:offset,end:until,scene:entry});
  }
  const root={...chapters[0].scene,chapters};
  return {scene:root,recognizedLines:totalLines,camera,note,sceneCount:chapters.length};
}
