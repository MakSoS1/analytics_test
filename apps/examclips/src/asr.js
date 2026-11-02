import {mono16k} from './media.js';
import {isSilent} from './audio-utils.js';
import {normalizeCheckpoint,remainingWindows} from './asr-checkpoint.js';
import {packWordEvents} from './word-align.js';
// One speech model for every lecture: NVIDIA Parakeet TDT 0.6B v3 (25 European
// languages incl. Russian and English, measured word timestamps). The first run
// downloads the weights from Hugging Face; audio stays local as Float32Arrays.
export const ASR_MODEL='parakeet-tdt-0.6b-v3';
export const ASR_MODEL_LABEL='NVIDIA Parakeet TDT 0.6B v3';
let transcriber=null,deviceName=null;
export async function getTranscriber(onProgress=()=>{}){
  if(transcriber)return {transcriber,deviceName};
  const [{fromHub},ort,{default:wasm}]=await Promise.all([import('parakeet.js'),import('onnxruntime-web'),
    import('onnxruntime-web/ort-wasm-simd-threaded.jsep.wasm?url')]);
  // Serve the ONNX Runtime binary from this site instead of a public CDN.
  ort.env.wasm.wasmPaths={wasm:new URL(wasm,location.href).href};
  const progress=({loaded,total,file})=>{if(total>0)onProgress('Модель распознавания ('+file+'): '+Math.round(loaded/total*100)+'%')};
  // WASM with the int8 encoder (0.67 GB) everywhere: the fp16 WebGPU encoder (1.2 GB)
  // fails to allocate its session in Chrome, and fp32 would be a 2.4 GB download.
  onProgress('Загрузка '+ASR_MODEL_LABEL+'. При первом запуске один раз скачивается около 0,7 ГБ, затем модель хранится в браузере.');
  transcriber=await fromHub(ASR_MODEL,{backend:'wasm',encoderQuant:'int8',decoderQuant:'int8',progress});
  deviceName='wasm';
  return {transcriber,deviceName};
}
export async function transcribe(media,{
 limit=Infinity,onProgress=()=>{},signal,
 resume=null,onCheckpoint=async()=>{}
}={}){
 const until=Math.min(media.duration,limit);
 const state=normalizeCheckpoint(resume,media.duration);
 let chunks=state.chunks.filter(c=>c.start<until);
 const done=new Set(state.completedWindows);
 const pending=remainingWindows(media.duration,limit,state.completedWindows);
 if(!pending.length){
  onProgress('Все запрошенные аудиоокна уже распознаны из локального кэша.');
  return chunks.sort((a,b)=>a.start-b.start);
 }
 const {transcriber:t}=await getTranscriber(onProgress);
 for(const start of pending){
   if(signal?.aborted)throw new DOMException('Stopped','AbortError');
   const end=Math.min(until,start+30);
   onProgress('Распознавание: '+Math.round(start)+'/'+Math.round(until)+' с (из кэша: '+done.size+' блоков)');
   const pcm=await mono16k(media.audioSink,start,end);
   if(!isSilent(pcm)){
     // Parakeet detects the language itself and measures every word's time.
     const result=await t.transcribe(pcm,16000,{returnTimestamps:true});
     const words=(result?.words||[]).map(w=>({text:w.text,timestamp:[w.start_time,w.end_time]}));
     if(words.length)chunks.push(...packWordEvents(words,start,end));
     else if(result?.utterance_text?.trim())chunks.push({start,end,text:result.utterance_text.trim()});
   }else onProgress('Тишина '+Math.round(start)+'–'+Math.round(end)+' с');
   done.add(start);
   chunks=chunks.sort((a,b)=>a.start-b.start);
   try{await onCheckpoint({chunks:[...chunks],completedWindows:[...done].sort((a,b)=>a-b)})}
   catch(e){onProgress('Не удалось сохранить локальную контрольную точку: '+e.message)}
 }
 return chunks;
}
