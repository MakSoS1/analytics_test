// Browser driver for the lecture virtual camera: decodes the ORIGINAL video on
// this device, downsamples frames and feeds the pure planner in visual-camera.js.
import {ANALYSIS_WIDTH,detectWebcam,createCameraIndexer} from './visual-camera.js';

const BATCH=60;
function analysisCanvas(media){
 const canvas=document.createElement('canvas');
 canvas.width=ANALYSIS_WIDTH;canvas.height=Math.max(2,Math.round(ANALYSIS_WIDTH*media.height/media.width));
 return {canvas,ctx:canvas.getContext('2d',{willReadFrequently:true})};
}
async function* framesAt(media,times,{canvas,ctx},signal){
 for(let offset=0;offset<times.length;offset+=BATCH){
  const slice=times.slice(offset,offset+BATCH);let index=0;
  for await(const sample of media.videoSink.samplesAtTimestamps(slice)){
   if(signal?.aborted){sample?.close();throw new DOMException('Stopped','AbortError')}
   const time=slice[index++];
   if(!sample)continue;
   try{
    ctx.clearRect(0,0,canvas.width,canvas.height);
    sample.draw(ctx,0,0,canvas.width,canvas.height);
    yield {time,rgba:ctx.getImageData(0,0,canvas.width,canvas.height).data.slice()};
   }finally{sample.close()}
  }
 }
}
/**
 * Indexes the whole lecture (or the given source ranges, e.g. one EDL) once.
 * Processing time is not limited: one analysis frame per `step` seconds.
 */
export async function indexLectureCamera(media,{ranges=null,step=1,signal,onProgress=()=>{}}={}){
 if(!media?.videoSink||!(media.duration>0))throw Error('No video samples');
 const parts=(ranges?.length?ranges:[{start:0,end:media.duration}])
  .map(r=>({start:Math.max(0,r.start),end:Math.min(media.duration-.05,r.end)})).filter(r=>r.end>r.start);
 const surface=analysisCanvas(media),w=surface.canvas.width,h=surface.canvas.height;
 const total=parts.reduce((n,r)=>n+r.end-r.start,0);
 // Webcam: persistent motion between frame pairs ~0.4 s apart across the lecture.
 onProgress('Камера: ищем окно лектора');
 const probes=[];
 const count=Math.min(40,Math.max(6,Math.round(total/20)));
 for(let i=0;i<count;i++){
  // Map an offset on the concatenated ranges back to source time.
  let rest=(i+.5)*total/count,part=parts.at(-1);
  for(const r of parts){if(rest<r.end-r.start){part=r;break}rest-=r.end-r.start}
  const t=Math.max(part.start,Math.min(part.end-.45,part.start+rest));
  probes.push(t,t+.4);
 }
 const probeFrames=[];
 for await(const frame of framesAt(media,probes,surface,signal))probeFrames.push(frame);
 const pairs=[];
 for(let i=0;i+1<probeFrames.length;i+=2)
  if(Math.abs(probeFrames[i+1].time-probeFrames[i].time-.4)<.01)pairs.push([probeFrames[i].rgba,probeFrames[i+1].rgba]);
 const webcam=detectWebcam(pairs,w,h);
 const indexer=createCameraIndexer({width:w,height:h,sourceWidth:media.width,sourceHeight:media.height,
  speaker:webcam?.box||null});
 let done=0;
 for(const part of parts){
  indexer.cut();
  const times=[];for(let t=part.start;t<part.end;t+=step)times.push(t);
  for await(const frame of framesAt(media,times,surface,signal)){
   indexer.push(frame.time,frame.rgba);
   if(++done%30===0)onProgress('Камера: '+Math.min(100,Math.round(done*step/total*100))+'% лекции');
  }
 }
 const track=indexer.finish(parts.at(-1).end);
 track.webcam=webcam?{confidence:webcam.confidence,edges:webcam.edges}:null;
 track.ranges=parts;
 onProgress('Камера готова: '+track.keys.length+' планов');
 return track;
}
