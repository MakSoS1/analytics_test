import {flattenOcr,makeStoryboard} from './scene-model.js';
import {motionFromMedia} from './speaker-motion.js';
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
  // Analyze only one representative frame in v1; future slide-change detection extends this.
  // No source frames or recognized text are sent to any API.
  const at=Math.min(media.duration-.05,clip.start+Math.min(2,(clip.end-clip.start)/3));
  const sample=await media.videoSink.getSample(Math.max(0,at));
  if(!sample)throw Error('Не удалось получить кадр для анализа');
  const canvas=createCanvas(media.width,media.height);
  try{sample.draw(canvas.getContext('2d'),0,0,media.width,media.height)}finally{sample.close()}
  if(signal?.aborted)throw new DOMException('Stopped','AbortError');
  let lines=[],note='';
  try{lines=await ocr(canvas,language,onProgress)}
  catch(error){note='OCR недоступен: '+error.message+'. Используется разбивка исходного слайда без интерпретации текста.'}
  if(signal?.aborted)throw new DOMException('Stopped','AbortError');
  let camera;try{camera=await motionFromMedia(media,clip,{signal})}
  catch(e){if(e.name==='AbortError')throw e;camera={found:false,box:{x:.815,y:.854,w:.18,h:.14},confidence:0}}
  const scene=makeStoryboard({width:media.width,height:media.height,speaker:camera.box,lines,duration:clip.end-clip.start,
    chunks:chunks.filter(c=>c.start<clip.end&&c.end>clip.start).map(c=>({...c,start:c.start-clip.start,end:c.end-clip.start}))});
  return {scene,recognizedLines:lines.length,camera,note};
}
