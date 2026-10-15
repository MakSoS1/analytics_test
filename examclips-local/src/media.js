import {Input,BlobSource,ALL_FORMATS,AudioBufferSink,VideoSampleSink} from 'mediabunny';
export async function openMedia(file){
  if(!file||file.size===0)throw Error('Пустой видеофайл');
  const input=new Input({source:new BlobSource(file),formats:ALL_FORMATS});
  try{
    const [videoTrack,audioTrack]=await Promise.all([input.getPrimaryVideoTrack(),input.getPrimaryAudioTrack()]);
    if(!videoTrack)throw Error('Не удалось найти видеодорожку');
    const duration=await videoTrack.computeDuration();
    if(!(duration>0&&Number.isFinite(duration)))throw Error('Не удалось определить длительность');
    return {input,videoTrack,audioTrack,duration,width:videoTrack.displayWidth,height:videoTrack.displayHeight,
      videoSink:new VideoSampleSink(videoTrack),audioSink:audioTrack?new AudioBufferSink(audioTrack):null};
  }catch(e){await input.dispose();throw e}
}
// Stream only 30 seconds of decoded audio at a time, mixing channels and resampling to 16 kHz.
export async function mono16k(sink,start,end){
  if(!sink)throw Error('В видео нет аудиодорожки');
  if(end<=start)throw Error('Некорректный аудиоинтервал');
  const n=Math.ceil((end-start)*16000),out=new Float32Array(n);
  for await(const item of sink.buffers(start,end)){
    const {buffer,timestamp}=item,rate=buffer.sampleRate;
    const left=buffer.getChannelData(0),right=buffer.numberOfChannels>1?buffer.getChannelData(1):null;
    const first=Math.max(0,Math.ceil((timestamp-start)*16000));
    const last=Math.min(n,Math.ceil((timestamp+buffer.duration-start)*16000));
    for(let i=first;i<last;i++){
      const p=(start+i/16000-timestamp)*rate,lo=Math.max(0,Math.min(left.length-1,Math.floor(p))),hi=Math.min(lo+1,left.length-1);
      const v=left[lo]+(left[hi]-left[lo])*(p-lo);
      const w=right?right[lo]+(right[hi]-right[lo])*(p-lo):v;
      out[i]=(v+w)/2;
    }
  }
  return out;
}
