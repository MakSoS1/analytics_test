import {flattenOcr,makeStoryboard} from './scene-model.js';
import {motionFromMedia} from './speaker-motion.js';
import {sampleSlideCuts} from './slide-cuts.js';
import {analyzeSlideContext,sourceEvidence,speechTarget} from './slide-context.js';

const createCanvas=(w,h)=>{const canvas=document.createElement('canvas');canvas.width=w;canvas.height=h;return canvas};
let worker=null,language='';
export async function detectLocalOcrCapability(){
  try{
    const response=await fetch('/api/local-ocr-capabilities',{cache:'no-store',signal:AbortSignal.timeout(2000)});
    return response.ok?(await response.json()).available===true:false;
  }catch{return false}
}
async function browserOcr(canvas,lang,onProgress){
  const target=lang==='ru'?'rus+eng':'eng';
  if(!worker||language!==target){
    if(worker){await worker.terminate();worker=null}
    const {createWorker}=await import('tesseract.js');
    onProgress('Загрузка Tesseract.js '+target+' (при первом запуске скачиваются языковые файлы)');
    worker=await createWorker(target,1,{logger:message=>{
      if(message.status==='recognizing text'&&message.progress!==undefined)
        onProgress('Распознавание доски: '+Math.round(message.progress*100)+'%');
    }});
    await worker.setParameters({tessedit_pageseg_mode:'11'});
    language=target;
  }
  const out=await worker.recognize(canvas,{}, {blocks:true});
  return {lines:flattenOcr(out.data.blocks||[]),engine:'Tesseract.js'};
}
async function localRapidOcr(canvas,lang,signal){
  const uri=canvas.toDataURL('image/png');
  const png_base64=uri.slice(uri.indexOf(',')+1);
  if(png_base64.length>4_700_000)throw Error('Изображение слишком большое для локального OCR');
  const response=await fetch('/api/local-ocr',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({language:lang==='ru'?'ru':'en',png_base64}),signal
  });
  let data;try{data=await response.json()}catch{throw Error('Локальный RapidOCR вернул недопустимый ответ')}
  if(!response.ok||!Array.isArray(data.lines))throw Error(data.error||'RapidOCR недоступен');
  return {lines:data.lines,engine:data.engine||'RapidOCR'};
}
export async function recognizeEducationalFrame(canvas,{
  language='en',engine='auto',onProgress=()=>{},signal
}={}){
  if(signal?.aborted)throw new DOMException('Stopped','AbortError');
  if(!['auto','tesseract','rapid'].includes(engine))throw Error('Unknown OCR engine');
  if(engine!=='tesseract'){
    if(await detectLocalOcrCapability()){
      try{
        onProgress('RapidOCR: распознавание на этом ПК без облачной загрузки');
        return await localRapidOcr(canvas,language,signal);
      }catch(err){
        if(signal?.aborted)throw new DOMException('Stopped','AbortError');
        onProgress('RapidOCR не смог обработать слайд: '+err.message+'. Переход к браузерному OCR.');
      }
    }else if(engine==='rapid')onProgress('RapidOCR пока не установлен. Переход к Tesseract.js.');
  }
  return browserOcr(canvas,language,onProgress);
}
export async function analyzeScene(media,clip,chunks,{
  language='en',ocrEngine='auto',onProgress=()=>{},signal
}={}){
  // Coarse slide detection first; OCR only at distinct changes.
  let cuts=[0],note='',totalLines=0;
  try{cuts=await sampleSlideCuts(media,clip,{signal,onProgress})}
  catch(e){if(e.name==='AbortError')throw e;note='Не удалось определить смены слайдов. '}
  let camera;
  try{camera=await motionFromMedia(media,clip,{signal})}
  catch(e){if(e.name==='AbortError')throw e;camera={found:false,box:{x:.815,y:.854,w:.18,h:.14},confidence:0}}
  const duration=clip.end-clip.start,chapters=[],usedEngines=new Set();
  for(let i=0;i<cuts.length;i++){
    if(signal?.aborted)throw new DOMException('Stopped','AbortError');
    const offset=cuts[i],until=cuts[i+1]??duration;
    const at=Math.min(media.duration-.05,clip.start+offset+Math.min(12,(until-offset)*.6));
    const sample=await media.videoSink.getSample(Math.max(0,at));
    if(!sample)throw Error('Не удалось получить учебный кадр');
    const canvas=createCanvas(media.width,media.height),ctx=canvas.getContext('2d',{willReadFrequently:true});
    try{sample.draw(ctx,0,0,media.width,media.height)}finally{sample.close()}
    let lines=[],backend='Original pixels';
    try{
      onProgress('Анализ структуры сцены '+(i+1)+'/'+cuts.length);
      const recognition=await recognizeEducationalFrame(canvas,{language,engine:ocrEngine,onProgress,signal});
      lines=recognition.lines;backend=recognition.engine;
    }catch(error){
      if(error.name==='AbortError')throw error;
      note+='OCR недоступен: '+error.message+'. Исходные рисунки сохранены. ';
    }
    usedEngines.add(backend);
    const pix=ctx.getImageData(0,0,media.width,media.height).data;
    const sampleRgb=(x,y)=>{
      const at=(y*media.width+x)*4;return [pix[at],pix[at+1],pix[at+2]];
    };
    const context=analyzeSlideContext(lines,media.width,media.height,{
      speaker:camera.box,sampleRgb
    });
    // Suppress logos/presenter text from sentence extraction and camera layer.
    const visible=sourceEvidence(lines,media.width,media.height,{speaker:camera.box})
      .filter(l=>!(l.box.y0<media.height*.18&&l.box.x0>media.width*.74&&l.text.length<=24));
    totalLines+=visible.length;
    const scoped=chunks.filter(c=>c.end>clip.start+offset&&c.start<clip.start+until)
      .map(c=>({...c,start:Math.max(0,c.start-clip.start-offset),end:Math.min(until-offset,c.end-clip.start-offset)}));
    const entry=makeStoryboard({width:media.width,height:media.height,speaker:camera.box,
      lines:visible,pixels:pix,duration:Math.max(.1,until-offset),chunks:scoped,
      titleOverride:clip.title||context.title||''});
    entry.context=context;
    entry.ocrBackend=backend;
    // A mention of an OCR-found UI tab/code block is a source-grounded attention cue.
    for(let b=0;b<entry.beats.length;b++){
      const now=entry.beats[b],next=entry.beats[b+1]?.time??until-offset;
      const spoken=scoped.filter(c=>c.end>now.time&&c.start<next).map(c=>c.text).join(' ');
      const target=speechTarget(context,spoken);
      if(target&&target.matchedTokens>0){
        const side=((target.box.x0+target.box.x1)/2)>=media.width*.5?'right':'left';
        now.focus=Math.max(0,entry.panels.findIndex(p=>p.id===side));
        now.evidence={type:target.type,text:target.text.slice(0,80),tokens:target.matchedTokens};
      }
    }
    chapters.push({start:offset,end:until,scene:entry});
  }
  const root={...chapters[0].scene,chapters};
  return {scene:root,recognizedLines:totalLines,camera,note,sceneCount:chapters.length,
    ocrBackend:[...usedEngines].join(', '),context:chapters[0].scene.context};
}
