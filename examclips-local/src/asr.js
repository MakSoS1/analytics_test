import {mono16k} from './media.js';
import {isSilent} from './audio-utils.js';
import {normalizeCheckpoint,remainingWindows} from './asr-checkpoint.js';
import {packWordEvents} from './word-align.js';
// First use of this module downloads the Whisper model from Hugging Face.
// Media/audio remains local: the ASR pipeline receives only Float32Arrays.
let transcriber=null,deviceName=null,activeModel=null,wordTimestampSupported=true;
const MODEL_IDS={tiny:'onnx-community/whisper-tiny',base:'onnx-community/whisper-base'};
export async function getTranscriber(onProgress=()=>{},model='tiny'){
  const modelId=MODEL_IDS[model];
  if(!modelId)throw Error('Неизвестная модель распознавания речи');
  if(transcriber&&activeModel===modelId)return {transcriber,deviceName};
  if(transcriber){try{await transcriber.dispose?.()}catch{}transcriber=null;deviceName=null}
  const {pipeline,env}=await import('@huggingface/transformers');
  env.allowRemoteModels=true;
  // navigator.gpu can exist in software/headless browsers with no usable adapter.
  const webgpu=!!(await navigator.gpu?.requestAdapter().catch(()=>null));
  let last;
  for(const device of webgpu?['webgpu','wasm']:['wasm']){
    try{
      onProgress('Загрузка '+modelId+' ('+device+'). При первом запуске скачиваются веса модели.');
      transcriber=await pipeline('automatic-speech-recognition',modelId,{
        device,progress_callback:e=>{if(e.status==='progress'&&e.progress!==undefined)onProgress(`Модель: ${Math.round(e.progress)}%`)}
      });
      deviceName=device;activeModel=modelId;return {transcriber,deviceName}
    }catch(e){last=e;onProgress('Режим '+device+' недоступен: '+e.message)}
  }
  throw last||Error('ASR unavailable');
}
export async function transcribe(media,{
 limit=Infinity,language='auto',model='tiny',onProgress=()=>{},signal,
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
 const {transcriber:t}=await getTranscriber(onProgress,model);
 for(const start of pending){
   if(signal?.aborted)throw new DOMException('Stopped','AbortError');
   const end=Math.min(until,start+30);
   onProgress('Whisper: '+Math.round(start)+'/'+Math.round(until)+' с (из кэша: '+done.size+' блоков)');
   const pcm=await mono16k(media.audioSink,start,end);
   if(!isSilent(pcm)){
     const opts={return_timestamps:wordTimestampSupported?'word':true,task:'transcribe'};
     if(language!=='auto')opts.language=language;
     let result;
     try{result=await t(pcm,opts)}
     catch(err){
       if(!wordTimestampSupported)throw err;
       // Certain ONNX Whisper variants do not support cross-attention word alignment.
       // Fall back to phrase timing, transparently estimating word placements later.
       wordTimestampSupported=false;
       onProgress('Слова по отдельности недоступны; продолжаю с таймкодами фраз.');
       result=await t(pcm,{...opts,return_timestamps:true});
     }
     if(result?.chunks?.length){
       const isWordOutput=wordTimestampSupported&&opts.return_timestamps==='word'&&
         result.chunks.length>=2&&result.chunks.every(item=>
           String(item.text||'').trim().split(/\s+/).length<=2);
       if(isWordOutput){
         chunks.push(...packWordEvents(result.chunks,start,end));
       }else{
         for(const item of result.chunks){
           if(!item.text?.trim())continue;
           const a=Array.isArray(item.timestamp)?item.timestamp:[0,end-start];
           const from=Math.min(end,start+Math.max(0,a[0]||0));
           const to=Math.min(end,start+(a[1]??end-start));
           if(to>from)chunks.push({start:from,end:to,text:item.text.trim()});
         }
       }
     }else if(result?.text?.trim()){
       chunks.push({start,end,text:result.text.trim()});
     }
   }else onProgress('Тишина '+Math.round(start)+'–'+Math.round(end)+' с');
   done.add(start);
   chunks=chunks.sort((a,b)=>a.start-b.start);
   try{await onCheckpoint({chunks:[...chunks],completedWindows:[...done].sort((a,b)=>a-b)})}
   catch(e){onProgress('Не удалось сохранить локальную контрольную точку: '+e.message)}
 }
 return chunks;
}
