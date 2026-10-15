import {Output,Mp4OutputFormat,BufferTarget,CanvasSource,AudioSampleSink,AudioSampleSource,Quality,canEncodeAudio} from 'mediabunny';
import {paintFrame,WIDTH,HEIGHT} from './composition.js';
import {validRange} from './segments.js';
import {captionCueAt} from './editorial-motion.js';
export async function exportClip(media,clip,chunks,{quality='standard',onProgress=()=>{},signal}={}){
  const high=quality==='high',fps=high?30:15;
  const outWidth=high?1080:WIDTH,outHeight=high?1920:HEIGHT;
  if(!validRange(clip.start,clip.end,media.duration))throw Error('Неверные границы клипа');
  if(typeof VideoEncoder==='undefined')throw Error('WebCodecs VideoEncoder недоступен. Нужен современный браузер.');
  if(media.audioTrack&&!(await canEncodeAudio('aac'))){const {registerAacEncoder}=await import('@mediabunny/aac-encoder');registerAacEncoder()}

  const canvas=document.createElement('canvas');canvas.width=outWidth;canvas.height=outHeight;
  const target=new BufferTarget(),output=new Output({format:new Mp4OutputFormat(),target});
  const videoSource=new CanvasSource(canvas,{codec:'avc',quality:new Quality('high')});
  output.addVideoTrack(videoSource);
  let audioSource=null;
  if(media.audioTrack){audioSource=new AudioSampleSource({codec:'aac',quality:new Quality('medium')});output.addAudioTrack(audioSource)}
  await output.start();
  const frames=Math.ceil((clip.end-clip.start)*fps);
  try{
    const times=Array.from({length:frames},(_,i)=>Math.min(clip.end-1e-5,clip.start+i/fps));
    let i=0;
    for await(const sample of media.videoSink.samplesAtTimestamps(times)){
      if(signal?.aborted)throw new DOMException('Stopped','AbortError');
      if(!sample)throw Error('Не удалось декодировать видеокадр '+i);
      try{
        paintFrame(canvas,sample,sample.displayWidth,sample.displayHeight,clip.layout,clip.focusX,captionCueAt(chunks,times[i]),clip.scene||null,times[i]-clip.start);
        await videoSource.add(i/fps,Math.min(1/fps,(clip.end-clip.start)-i/fps));
      }finally{sample.close()}
      i++;if(i%30===0||i===frames)onProgress(`Видео ${i}/${frames} кадров`);
    }
    if(audioSource){
      onProgress('Добавление оригинальной аудиодорожки...');
      for await(const raw of new AudioSampleSink(media.audioTrack).samples(clip.start,clip.end)){
        if(signal?.aborted){raw.close();throw new DOMException('Stopped','AbortError')}
        let sample=raw;
        try{
          const first=Math.max(0,Math.round((clip.start-raw.timestamp)*raw.sampleRate));
          const last=Math.min(raw.numberOfFrames,Math.round((clip.end-raw.timestamp)*raw.sampleRate));
          if(last<=first)continue;
          if(first>0||last<raw.numberOfFrames)sample=raw.trim(first,last);
          sample.setTimestamp(Math.max(0,sample.timestamp-clip.start));
          await audioSource.add(sample);
        }finally{if(sample!==raw)sample.close();raw.close()}
      }
    }
    await output.finalize();
    if(!target.buffer)throw Error('Кодировщик не вернул MP4');
    return new Blob([target.buffer],{type:'video/mp4'});
  }catch(e){
    try{await output.cancel()}catch{}
    throw e;
  }
}
