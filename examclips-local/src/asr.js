import {mono16k} from './media.js';
// First use of this module downloads the Whisper model from Hugging Face.
// Media/audio remains local: the ASR pipeline receives only Float32Arrays.
let transcriber=null,deviceName=null;
export async function getTranscriber(onProgress=()=>{}){
  if(transcriber)return {transcriber,deviceName};
  const {pipeline,env}=await import('@huggingface/transformers');
  env.allowRemoteModels=true;
  const webgpu=!!navigator.gpu;
  let last;
  for(const device of webgpu?['webgpu','wasm']:['wasm']){
    try{
      onProgress('Загрузка Whisper tiny ('+device+'). При первом запуске скачиваются веса модели.');
      transcriber=await pipeline('automatic-speech-recognition','onnx-community/whisper-tiny',{
        device,progress_callback:e=>{if(e.status==='progress'&&e.progress!==undefined)onProgress(`Модель: ${Math.round(e.progress)}%`)}
      });
      deviceName=device;return {transcriber,deviceName}
    }catch(e){last=e;onProgress('Режим '+device+' недоступен: '+e.message)}
  }
  throw last||Error('ASR unavailable');
}
export async function transcribe(media,{limit=Infinity,language='auto',onProgress=()=>{},signal}={}){
  const {transcriber:t}=await getTranscriber(onProgress);
  const until=Math.min(media.duration,limit),chunks=[];
  for(let start=0;start<until;start+=30){
    if(signal?.aborted)throw new DOMException('Stopped','AbortError');
    const end=Math.min(until,start+30);
    onProgress(`Whisper: ${Math.round(start)}/${Math.round(until)} с`);
    const pcm=await mono16k(media.audioSink,start,end);
    const opts={return_timestamps:true,task:'transcribe'};
    if(language!=='auto')opts.language=language;
    const result=await t(pcm,opts);
    if(result?.chunks?.length){
      for(const item of result.chunks){
        if(!item.text?.trim())continue;
        const a=Array.isArray(item.timestamp)?item.timestamp:[0,end-start];
        chunks.push({start:start+Math.max(0,a[0]||0),end:Math.min(end,start+(a[1]??end-start)),text:item.text.trim()});
      }
    }else if(result?.text?.trim()){
      // Coarse timestamps are explicitly approximate if the model did not return chunks.
      chunks.push({start,end,text:result.text.trim()});
    }
  }
  return chunks.filter(c=>c.end>c.start);
}
