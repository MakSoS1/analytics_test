// Lightweight slide transition detector: compares downsampled original pixels,
// ignoring the webcam strip, no remote image service or inference.
export function slideDifference(a,b,width=160,height=90,{threshold=38}={}){
 if(!a||!b||a.length!==b.length||a.length!==width*height*4)throw Error('Invalid RGBA samples');
 let count=0,changed=0;
 for(let y=2;y<Math.floor(height*.81);y+=2)for(let x=2;x<width-2;x+=2){
  const k=(y*width+x)*4;
  const d=Math.max(Math.abs(a[k]-b[k]),Math.abs(a[k+1]-b[k+1]),Math.abs(a[k+2]-b[k+2]));
  changed+=(d>threshold?1:0);count++;
 }
 return count?changed/count:0;
}
export function detectSceneCuts(samples,{minGap=9,difference=.085,maxScenes=6}={}){
 if(!samples?.length)return [0];
 const ordered=[...samples].sort((a,b)=>a.time-b.time);
 let latest=ordered[0],cuts=[0];
 for(let i=1;i<ordered.length&&cuts.length<maxScenes;i++){
   const sample=ordered[i];
   if(sample.time-cuts.at(-1)<minGap)continue;
   if(slideDifference(latest.rgba,sample.rgba,sample.width,sample.height)>difference){
     cuts.push(sample.time);latest=sample;
   }
 }
 return cuts;
}
export async function sampleSlideCuts(media,clip,{signal,onProgress=()=>{},sampleEvery=8}={}){
 const duration=clip.end-clip.start;
 if(duration<16)return [0];
 const w=160,h=90,canvas=document.createElement('canvas');canvas.width=w;canvas.height=h;
 const ctx=canvas.getContext('2d',{willReadFrequently:true}),samples=[];
 for(let t=0;t<duration;t+=sampleEvery){
   if(signal?.aborted)throw new DOMException('Stopped','AbortError');
   const sample=await media.videoSink.getSample(Math.min(clip.end-.05,clip.start+t+.5));
   if(!sample)continue;
   try{
      ctx.clearRect(0,0,w,h);sample.draw(ctx,0,0,w,h);
      samples.push({time:t,width:w,height:h,rgba:ctx.getImageData(0,0,w,h).data.slice()});
   }finally{sample.close()}
 }
 const cuts=detectSceneCuts(samples,{maxScenes:Math.min(120,Math.max(6,Math.ceil(duration/30)))});
 onProgress('Смены слайдов: '+Math.max(0,cuts.length-1));
 return cuts;
}
