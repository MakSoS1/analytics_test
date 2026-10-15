// Local temporal-motion webcam locator. No network, no neural model.
// The fallback geometry is a documented preset, not reliable speaker recognition.
export const CANDIDATES=[
  {name:'bottom-right',box:{x:.80,y:.82,w:.20,h:.18}},
  {name:'bottom-left',box:{x:0,y:.82,w:.20,h:.18}},
  {name:'top-right',box:{x:.80,y:0,w:.20,h:.18}},
  {name:'top-left',box:{x:0,y:0,w:.20,h:.18}},
  {name:'bottom-center',box:{x:.4,y:.82,w:.20,h:.18}}
];
export function detectMotionROI(images,width,height,{threshold=20,minimumMotion=.008}={}){
 if(!Array.isArray(images)||images.length<2)return {box:CANDIDATES[0].box,confidence:0,found:false};
 if(images.some(image=>!image||image.length!==width*height*4))throw Error('Mismatched RGBA input');
 const rows=[];
 for(const c of CANDIDATES){
   const x0=Math.floor(c.box.x*width),y0=Math.floor(c.box.y*height);
   const x1=Math.min(width,Math.ceil((c.box.x+c.box.w)*width)),y1=Math.min(height,Math.ceil((c.box.y+c.box.h)*height));
   let sum=0,n=0;
   for(let k=0;k<images.length-1;k++){
     const a=images[k],b=images[k+1];
     for(let y=y0;y<y1;y+=2)for(let x=x0;x<x1;x+=2){
       const off=(y*width+x)*4;
       const delta=Math.max(Math.abs(a[off]-b[off]),Math.abs(a[off+1]-b[off+1]),Math.abs(a[off+2]-b[off+2]));
       sum+=(delta>threshold?1:0);n++;
     }
   }
   rows.push({...c,score:n?sum/n:0});
 }
 rows.sort((a,b)=>b.score-a.score);
 const best=rows[0],runnerUp=rows[1]?.score||0;
 const found=best.score>=minimumMotion && best.score>runnerUp*1.45;
 return {box:found?best.box:CANDIDATES[0].box,confidence:found?best.score:0,found,candidate:found?best.name:'fallback-bottom-right',scores:rows.map(({name,score})=>({name,score}))};
}
export async function motionFromMedia(media,clip,{signal}={}){
 const duration=clip.end-clip.start;
 if(duration<4)return {box:CANDIDATES[0].box,confidence:0,found:false};
 const times=[clip.start+Math.min(1,duration*.10),clip.start+Math.min(3,duration*.35),clip.start+Math.min(5,duration*.6)];
 const canvas=document.createElement('canvas');canvas.width=320;canvas.height=180;
 const ctx=canvas.getContext('2d',{willReadFrequently:true}),images=[];
 for(const t of times){
   if(signal?.aborted)throw new DOMException('Stopped','AbortError');
   const sample=await media.videoSink.getSample(t);if(!sample)continue;
   try{ctx.clearRect(0,0,320,180);sample.draw(ctx,0,0,320,180);
     images.push(ctx.getImageData(0,0,320,180).data.slice());
   }finally{sample.close()}
 }
 return detectMotionROI(images,320,180);
}
