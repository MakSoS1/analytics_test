import {Output,Mp4OutputFormat,BufferTarget,CanvasSource,AudioSampleSink,AudioSampleSource,Quality,canEncodeAudio} from 'mediabunny';
import {paintFrame,WIDTH,HEIGHT} from './composition.js';
import {captionSequenceAt} from './caption-flow.js';
import {sourceSegments,storyDuration} from './selective-stories.js';

/**
 * Nonlinear edit list (EDL): pieces are decoded from the original video
 * in the chosen order, and both video and PCM audio are re-timestamped onto
 * a continuous destination timeline. No cloud rendering and no silent gaps.
 */
export async function exportClip(media,clip,chunks,{quality='standard',onProgress=()=>{},signal}={}){
 const high=quality==='high',fps=high?30:15;
 const width=high?1080:WIDTH,height=high?1920:HEIGHT;
 const pieces=sourceSegments(clip),total=storyDuration(clip);
 if(!pieces.length||!(total>.05)||pieces.some(s=>s.start<0||s.end>media.duration||s.end<=s.start))
   throw Error('Недопустимые интервалы исходного видео');
 if(total>601)throw Error('Клип больше 10 минут: разбейте микротему на несколько видео');
 if(typeof VideoEncoder==='undefined')throw Error('WebCodecs VideoEncoder недоступен. Нужен современный браузер.');
 if(media.audioTrack&&!(await canEncodeAudio('aac'))){
  const {registerAacEncoder}=await import('@mediabunny/aac-encoder');registerAacEncoder();
 }
 const canvas=document.createElement('canvas');canvas.width=width;canvas.height=height;
 const target=new BufferTarget(),output=new Output({format:new Mp4OutputFormat(),target});
 const videoSource=new CanvasSource(canvas,{codec:'avc',quality:new Quality('high')});
 output.addVideoTrack(videoSource);
 let audioSource=null;
 if(media.audioTrack){audioSource=new AudioSampleSource({codec:'aac',quality:new Quality('medium')});output.addAudioTrack(audioSource)}
 await output.start();
 const frameCounts=pieces.map(p=>Math.max(1,Math.ceil((p.end-p.start)*fps)));
 const frames=frameCounts.reduce((n,c)=>n+c,0);
 let videoOffset=0,done=0,audioOffset=0;
 try{
   for(let index=0;index<pieces.length;index++){
     const section=pieces[index],duration=section.end-section.start;
     const n=frameCounts[index];
     const times=Array.from({length:n},(_,i)=>Math.min(section.end-1e-5,section.start+i/fps));
     let pos=0;
     for await(const frame of media.videoSink.samplesAtTimestamps(times)){
       if(signal?.aborted)throw new DOMException('Stopped','AbortError');
       if(!frame)throw Error('Не удалось декодировать кадр '+done);
       try{
         paintFrame(canvas,frame,frame.displayWidth,frame.displayHeight,
           clip.layout,clip.focusX,captionSequenceAt(chunks,times[pos]),
           clip.scenes?.[index]||clip.scene||null,pos/fps);
         // Continuous output time across disjoint parts; no 300s silent gap.
         const pts=videoOffset+pos/fps;
         const frameDuration=Math.max(.00001,Math.min(1/fps,videoOffset+duration-pts));
         await videoSource.add(pts,frameDuration);
       }finally{frame.close()}
       pos++;done++;
       if(done%30===0||done===frames)onProgress('Видео '+done+'/'+frames+' кадров · фрагмент '+(index+1)+'/'+pieces.length);
     }
     if(pos!==n)throw Error('Неполная декомпрессия сегмента '+(index+1));
     videoOffset+=duration;
   }
   if(audioSource){
     onProgress('Склеиваем исходную звуковую дорожку по выбранным фрагментам...');
     for(let index=0;index<pieces.length;index++){
       const p=pieces[index],duration=p.end-p.start;
       for await(const raw of new AudioSampleSink(media.audioTrack).samples(p.start,p.end)){
         if(signal?.aborted){raw.close();throw new DOMException('Stopped','AbortError')}
         let sample=raw;
         try{
           const first=Math.max(0,Math.round((p.start-raw.timestamp)*raw.sampleRate));
           const last=Math.min(raw.numberOfFrames,Math.round((p.end-raw.timestamp)*raw.sampleRate));
           if(last<=first)continue;
           if(first>0||last<raw.numberOfFrames)sample=raw.trim(first,last);
           sample.setTimestamp(audioOffset+Math.max(0,sample.timestamp-p.start));
           await audioSource.add(sample);
         }finally{if(sample!==raw)sample.close();raw.close()}
       }
       audioOffset+=duration;
     }
   }
   await output.finalize();
   if(!target.buffer)throw Error('Кодировщик не вернул MP4');
   return new Blob([target.buffer],{type:'video/mp4'});
 }catch(err){try{await output.cancel()}catch{}throw err}
}
