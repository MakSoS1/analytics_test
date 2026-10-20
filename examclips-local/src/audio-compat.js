import {AudioBufferSink,AudioSampleSink,AudioSample,EncodedPacketSink,EncodedAudioPacketSource,Output,AdtsOutputFormat,BufferTarget} from 'mediabunny';

// Some Chromium derivatives report AAC support but reject configure(). Probe a
// real sample before loading Whisper. Web Audio uses a separate decoder path.
export async function compatibleAudio(track){
 if(!track)return {audioSink:null,audioSampleSink:null,audioDecoding:'none'};
 const native=new AudioBufferSink(track);
 try{
  const first=await track.getFirstTimestamp();
  await native.getBuffer(Math.max(0,first)+.05);
  return {audioSink:native,audioSampleSink:new AudioSampleSink(track),audioDecoding:'webcodecs'};
 }catch(error){
  if(track.codec!=='aac')throw new Error('Браузер не смог прочитать звуковую дорожку ('+track.codec+'). Откройте файл в актуальном Chrome или Edge.',{cause:error});
 }
 const fallback=new WindowedWebAudio(track);
 // Validate the alternate path immediately; do not spend time loading ASR first.
 for await(const _ of fallback.buffers(0,.12))break;
 return {audioSink:fallback,audioSampleSink:fallback,audioDecoding:'webaudio'};
}
class WindowedWebAudio{
 constructor(track){this.track=track}
 async *buffers(start=0,end=Infinity){
  const track=this.track,until=Math.min(end,await track.computeDuration());
  for(let at=start;at<until;at+=30){
   const stop=Math.min(until,at+30),packets=new EncodedPacketSink(track);
   // AAC overlap/add needs preceding frames when seeking into a lecture.
   const first=await packets.getPacket(Math.max(0,at-.15))||await packets.getFirstPacket();
   if(!first)continue;
   // ADTS avoids the implicit AAC priming trim applied to short MP4s by Web Audio.
   const target=new BufferTarget(),output=new Output({format:new AdtsOutputFormat(),target});
   const source=new EncodedAudioPacketSource('aac');output.addAudioTrack(source);await output.start();
   const config=await track.getDecoderConfig(),origin=first.timestamp;
   let initial=true;
   try{
    for await(const packet of packets.packets(first)){
     if(packet.timestamp>=stop+.05)break;
     await source.add(packet.clone({timestamp:packet.timestamp-origin}),initial?{decoderConfig:config}:undefined);initial=false;
    }
    await output.finalize();
   }catch(error){try{await output.cancel()}catch{}throw error}
   const Context=globalThis.AudioContext||globalThis.webkitAudioContext;
   if(!Context)throw Error('Браузер не поддерживает локальное чтение звука. Откройте лекцию в актуальном Chrome или Edge.');
   const context=new Context({sampleRate:track.sampleRate});
   let decoded;
   try{decoded=await context.decodeAudioData(target.buffer)}
   catch(error){throw new Error('Браузер не смог прочитать AAC-звук ни одним доступным способом. Попробуйте актуальный Chrome или Edge.',{cause:error})}
   finally{await context.close()}
   const lo=Math.max(0,Math.round((at-origin)*decoded.sampleRate));
   const hi=Math.min(decoded.length,Math.round((stop-origin)*decoded.sampleRate));
   if(hi<=lo)continue;
   const buffer=new AudioBuffer({length:hi-lo,sampleRate:decoded.sampleRate,numberOfChannels:decoded.numberOfChannels});
   for(let c=0;c<buffer.numberOfChannels;c++)buffer.copyToChannel(decoded.getChannelData(c).subarray(lo,hi),c);
   yield {buffer,timestamp:origin+lo/decoded.sampleRate,duration:buffer.duration};
  }
 }
 async *samples(start,end){
  for await(const {buffer,timestamp} of this.buffers(start,end)){
   const samples=AudioSample.fromAudioBuffer(buffer,timestamp);
   try{for(const sample of samples)yield sample}
   finally{for(const sample of samples)sample.close()}
  }
 }
}
