// Lecture "virtual camera": a SOURCE-time track of vertical crops that follows
// what the lecturer shows (new slide content, reveals, typing, pointer work).
// Pure pixel heuristics on downscaled RGBA frames: no network, no model.
// Coordinates in the track are normalized to the source frame.
import {cameraStageAspect} from './editorial-motion.js';
export const ANALYSIS_WIDTH=640;
// Stage of the editorial layout with a compact presenter strip (see editorialGeometry).
export const STAGE={w:684,h:820};
const clamp=(n,a,b)=>Math.min(b,Math.max(a,n));
const rect=(x,y,w,h)=>({x,y,w,h});
const area=r=>r.w*r.h;
function overlap(a,b){
 return Math.max(0,Math.min(a.x+a.w,b.x+b.w)-Math.max(a.x,b.x))*
   Math.max(0,Math.min(a.y+a.h,b.y+b.h)-Math.max(a.y,b.y));
}
export function iou(a,b){const o=overlap(a,b);return o/Math.max(1e-9,area(a)+area(b)-o)}
export function union(list){
 const x0=Math.min(...list.map(r=>r.x)),y0=Math.min(...list.map(r=>r.y));
 const x1=Math.max(...list.map(r=>r.x+r.w)),y1=Math.max(...list.map(r=>r.y+r.h));
 return rect(x0,y0,x1-x0,y1-y0);
}
function excludedMask(w,h,exclude=[]){
 const mask=new Uint8Array(w*h);
 for(const r of exclude||[]){
  const x0=clamp(Math.floor(r.x*w),0,w),x1=clamp(Math.ceil((r.x+r.w)*w),0,w);
  const y0=clamp(Math.floor(r.y*h),0,h),y1=clamp(Math.ceil((r.y+r.h)*h),0,h);
  for(let y=y0;y<y1;y++)mask.fill(1,y*w+x0,y*w+x1);
 }
 return mask;
}
/** Dominant (background) colour: mode of a 4-bit/channel histogram. */
export function backgroundColor(rgba,w,h,skip=null){
 const counts=new Uint32Array(4096),sums=new Float64Array(4096*3);
 for(let i=0;i<w*h;i+=2){
  if(skip?.[i])continue;
  const k=i*4,bin=(rgba[k]>>4)<<8|(rgba[k+1]>>4)<<4|(rgba[k+2]>>4);
  counts[bin]++;sums[bin*3]+=rgba[k];sums[bin*3+1]+=rgba[k+1];sums[bin*3+2]+=rgba[k+2];
 }
 let best=0;for(let b=1;b<4096;b++)if(counts[b]>counts[best])best=b;
 const n=Math.max(1,counts[best]);
 return [sums[best*3]/n,sums[best*3+1]/n,sums[best*3+2]/n];
}
function label(mask,w,h,eight=true){
 const labels=new Int32Array(w*h),comps=[],stack=[];
 for(let start=0;start<w*h;start++){
  if(!mask[start]||labels[start])continue;
  const id=comps.length+1,c={id,count:0,x0:w,y0:h,x1:0,y1:0};
  labels[start]=id;stack.push(start);
  while(stack.length){
   const p=stack.pop(),x=p%w,y=(p-x)/w;
   c.count++;if(x<c.x0)c.x0=x;if(x>c.x1)c.x1=x;if(y<c.y0)c.y0=y;if(y>c.y1)c.y1=y;
   for(let dy=-1;dy<=1;dy++)for(let dx=-1;dx<=1;dx++){
    if((!dx&&!dy)||(!eight&&dx&&dy))continue;
    const nx=x+dx,ny=y+dy;if(nx<0||ny<0||nx>=w||ny>=h)continue;
    const q=ny*w+nx;if(mask[q]&&!labels[q]){labels[q]=id;stack.push(q)}
   }
  }
  comps.push(c);
 }
 return {labels,comps};
}
/** Pixels that differ from the slide background, excluding webcam/other regions. */
export function foregroundMask(rgba,w,h,{exclude=[],threshold=42}={}){
 const skip=excludedMask(w,h,exclude),bg=backgroundColor(rgba,w,h,skip),mask=new Uint8Array(w*h);
 for(let i=0;i<w*h;i++){
  if(skip[i])continue;const k=i*4;
  if(Math.max(Math.abs(rgba[k]-bg[0]),Math.abs(rgba[k+1]-bg[1]),Math.abs(rgba[k+2]-bg[2]))>threshold)mask[i]=1;
 }
 return mask;
}
/**
 * Removes long thin strokes: template curves, card borders, separators, arrows.
 * Glyphs are short and filled pictures survive a morphological opening, so
 * readable content stays while decoration no longer inflates content boxes.
 */
function crossStep(src,w,h,erode){
 const out=new Uint8Array(w*h);
 for(let y=1;y<h-1;y++)for(let x=1;x<w-1;x++){
  const i=y*w+x,a=src[i],l=src[i-1],r=src[i+1],u=src[i-w],d=src[i+w];
  if(erode?(a&&l&&r&&u&&d):(a||l||r||u||d))out[i]=1;
 }
 return out;
}
/** Morphological opening with a cross of the given radius. */
export function opening(mask,w,h,radius=2){
 let m=mask;
 for(let i=0;i<radius;i++)m=crossStep(m,w,h,true);
 for(let i=0;i<radius;i++)m=crossStep(m,w,h,false);
 return m;
}
export function removeStrokes(mask,w,h,{minLength=Math.round(w*.08)}={}){
 // Radius 2 also treats 3-4 px template curves of a 640 px analysis frame as lines.
 const opened=opening(mask,w,h,2);
 const thin=new Uint8Array(w*h);
 for(let i=0;i<w*h;i++)if(mask[i]&&!opened[i])thin[i]=1;
 const {labels,comps}=label(thin,w,h,true);
 const stroke=new Uint8Array(comps.length+1);
 for(const c of comps){
  const bw=c.x1-c.x0+1,bh=c.y1-c.y0+1;
  const long=Math.max(bw,bh),density=c.count/(bw*bh);
  // Long lines and curves; shorter sparse arcs are rounded card corners.
  if((long>=minLength&&(density<.12||Math.min(bw,bh)<=2))||(long>=minLength*.28&&density<.1))stroke[c.id]=1;
 }
 const out=mask.slice();
 for(let i=0;i<w*h;i++)if(stroke[labels[i]])out[i]=0;
 return out;
}
function dilate(mask,w,h,rx,ry){
 const tmp=new Uint8Array(w*h),out=new Uint8Array(w*h);
 for(let y=0;y<h;y++){
  let last=-1e9;
  for(let x=0;x<w;x++){if(mask[y*w+x])last=x;if(x-last<=rx)tmp[y*w+x]=1}
  last=1e9;
  for(let x=w-1;x>=0;x--){if(mask[y*w+x])last=x;if(last-x<=rx)tmp[y*w+x]=1}
 }
 for(let x=0;x<w;x++){
  let last=-1e9;
  for(let y=0;y<h;y++){if(tmp[y*w+x])last=y;if(y-last<=ry)out[y*w+x]=1}
  last=1e9;
  for(let y=h-1;y>=0;y--){if(tmp[y*w+x])last=y;if(last-y<=ry)out[y*w+x]=1}
 }
 return out;
}
/** Large solid regions slightly off the background: picture/diagram backdrops. */
export function backdropPanels(rgba,w,h,exclude=[]){
 const soft=foregroundMask(rgba,w,h,{exclude,threshold:3});
 const {comps}=label(opening(soft,w,h,3),w,h,false);
 return comps.map(c=>rect(c.x0/w,c.y0/h,(c.x1-c.x0+1)/w,(c.y1-c.y0+1)/h))
  .filter(r=>area(r)>=.03&&area(r)<=.7&&r.w<.95);
}
/**
 * Reading-ordered content blocks (normalized): diagrams, bullet lists, code.
 * Neighbouring lines join; separate columns and pictures stay separate.
 */
export function contentBlocks(rgba,w,h,{exclude=[],titleBand=.17}={}){
 const mask=removeStrokes(foregroundMask(rgba,w,h,{exclude}),w,h);
 const grown=dilate(mask,w,h,Math.round(w*.016),Math.round(h*.024));
 const {labels,comps}=label(grown,w,h,false);
 const boxes=comps.map(()=>({count:0,x0:w,y0:h,x1:-1,y1:-1}));
 for(let i=0;i<w*h;i++){
  if(!mask[i])continue;const b=boxes[labels[i]-1],x=i%w,y=(i-x)/w;
  b.count++;if(x<b.x0)b.x0=x;if(x>b.x1)b.x1=x;if(y<b.y0)b.y0=y;if(y>b.y1)b.y1=y;
 }
 // A heading set just above the content joins it through dilation; split the
 // block at the blank row nearest the heading band.
 const band=Math.round(h*titleBand);
 for(const [index,b] of [...boxes.entries()]){
  if(!b.count||b.y0>=band||b.y1<band+h*.04)continue;
  const id=index+1,blank=y=>{for(let x=b.x0;x<=b.x1;x++)if(mask[y*w+x]&&labels[y*w+x]===id)return false;return true};
  let cut=-1;
  for(let y=Math.min(b.y1-1,band+Math.round(h*.05));y>b.y0+2;y--)if(blank(y)){cut=y;break}
  if(cut<0)continue;
  const top={count:0,x0:w,y0:h,x1:-1,y1:-1},bottom={count:0,x0:w,y0:h,x1:-1,y1:-1};
  for(let y=b.y0;y<=b.y1;y++)for(let x=b.x0;x<=b.x1;x++){
   const i=y*w+x;if(!mask[i]||labels[i]!==id)continue;
   const t=y<cut?top:bottom;
   t.count++;if(x<t.x0)t.x0=x;if(x>t.x1)t.x1=x;if(y<t.y0)t.y0=y;if(y>t.y1)t.y1=y;
  }
  boxes[index]=top;boxes.push(bottom);
 }
 let blocks=boxes.filter(b=>b.count>=w*h*.0006&&(b.x1-b.x0+1)*(b.y1-b.y0+1)>=w*h*.002)
  .map(b=>({...rect(b.x0/w,b.y0/h,(b.x1-b.x0+1)/w,(b.y1-b.y0+1)/h),pixels:b.count/(w*h)}));
 // Bounding boxes of interleaved shapes can overlap; one region per object.
 for(let merged=true;merged;){
  merged=false;
  outer:for(let i=0;i<blocks.length;i++)for(let j=i+1;j<blocks.length;j++){
   const a=blocks[i],b=blocks[j],o=overlap(a,b);
   if(o>Math.min(area(a),area(b))*.25){
    blocks[i]={...union([a,b]),pixels:a.pixels+b.pixels};blocks.splice(j,1);merged=true;break outer;
   }
  }
 }
 // Pieces of one picture share its tinted backdrop (a pasted diagram or
 // screenshot): show them together rather than as separate fragments.
 const panels=backdropPanels(rgba,w,h,exclude);
 for(const panel of panels){
  const inside=blocks.filter(b=>overlap(b,panel)>=area(b)*.6);
  if(inside.length<2)continue;
  blocks=[...blocks.filter(b=>!inside.includes(b)),
   {...union(inside),pixels:inside.reduce((n,b)=>n+b.pixels,0)}];
 }
 // A code listing or list continues after a blank line at the same left edge.
 for(let merged=true;merged;){
  merged=false;
  outer:for(const a of blocks)for(const b of blocks){
   if(a===b||b.y<a.y||a.y+a.h<titleBand+.02)continue;
   const gap=b.y-(a.y+a.h);
   if(gap>=0&&gap<.07&&Math.abs(a.x-b.x)<.015){
    blocks=[...blocks.filter(x=>x!==a&&x!==b),{...union([a,b]),pixels:a.pixels+b.pixels}];
    merged=true;break outer;
   }
  }
 }
 // The slide heading and logos are not what the lecturer explains.
 const body=blocks.filter(b=>b.y+b.h>titleBand+.02);
 if(body.length)blocks=body;
 // Tiny isolated marks (window buttons, icons) are not content when real blocks exist.
 const real=blocks.filter(b=>area(b)>=.003);
 if(real.length)blocks=real;
 const column=b=>Math.floor((b.x+b.w*.1)*3);
 return blocks.sort((a,b)=>column(a)-column(b)||a.y-b.y);
}
/** Changed area between consecutive analysis frames (webcam excluded). */
export function changeRegion(prev,cur,w,h,{exclude=[],threshold=40}={}){
 const skip=excludedMask(w,h,exclude),cols=new Uint32Array(w),rows=new Uint32Array(h);
 let changed=0,count=0;
 for(let y=0;y<h;y++)for(let x=0;x<w;x++){
  const i=y*w+x;if(skip[i])continue;count++;
  const k=i*4;
  if(Math.max(Math.abs(prev[k]-cur[k]),Math.abs(prev[k+1]-cur[k+1]),Math.abs(prev[k+2]-cur[k+2]))>threshold){
   changed++;cols[x]++;rows[y]++;
  }
 }
 const fraction=count?changed/count:0;
 if(changed<Math.max(12,w*h*.00025))return {fraction,box:null};
 // Trim isolated codec noise from the extent.
 const span=(hist,n)=>{let a=0,b=n-1;while(a<n&&hist[a]<2)a++;while(b>a&&hist[b]<2)b--;return a<=b?[a,b]:null};
 const xs=span(cols,w),ys=span(rows,h);
 if(!xs||!ys)return {fraction,box:null};
 return {fraction,box:rect(xs[0]/w,ys[0]/h,(xs[1]-xs[0]+1)/w,(ys[1]-ys[0]+1)/h)};
}
/**
 * Vertical crop showing a content box: fills the stage (no letterbox), keeps the
 * whole box when it can be read, otherwise returns a left→right pan pair.
 */
export function frameContent(box,{sourceWidth,sourceHeight,aspect=STAGE.w/STAGE.h,stageWidth=STAGE.w,
  minZoom=.75,maxZoom=1.45,pad=.035,avoid=null,band=.185}={}){
 const W=sourceWidth,H=sourceHeight;
 let x0=(box.x-pad)*W,x1=(box.x+box.w+pad)*W,y0=(box.y-pad)*H,y1=(box.y+box.h+pad)*H;
 let bw=x1-x0,bh=y1-y0,cx=(x0+x1)/2,cy=(y0+y1)/2;
 let cw=Math.max(bw,bh*aspect);
 cw=clamp(cw,stageWidth/maxZoom,stageWidth/minZoom);
 let ch=cw/aspect;
 // A vertical crop of a landscape source is bounded by its height.
 if(ch>H){ch=H;cw=ch*aspect}
 if(cw>W){cw=W;ch=Math.min(H,cw/aspect)}
 const blockTop=Math.max(0,y0);
 const place=(centerX)=>{
  let w=cw,h=ch,x=clamp(centerX-w/2,0,W-w);
  // Reading starts at the top of the content. Never show a sliver of the slide
  // heading: start below the heading band unless the content itself is in it.
  let y=y0-h*.06;
  // Content that continues below the heading band is framed without the heading.
  // (A full-slide picture that starts at the top edge keeps its top.)
  const minTop=box.y>=band-.08&&box.y+box.h>band+.05?band*H:0;
  if(y<minTop)y=minTop;
  y=clamp(y,0,H-h);
  // A tall shot pushed up by the slide's bottom edge must not climb into the
  // heading again: start below it and keep the full width (pinned to the top).
  let pinned=false;
  if(y<minTop){y=minTop;h=H-minTop;pinned=true}
  // Keep the slide's own webcam tile out of the shot: it is already shown below.
  if(avoid){
   const ax=avoid.x*W,ay=avoid.y*H,inside=()=>x+w>ax&&y+h>ay;
   if(inside()&&ay-h>=minTop&&ay-h<=blockTop)y=ay-h;
   // Sideways only when the whole block stays left of the tile.
   if(inside()&&x1<=ax&&ax-w>=0&&ax-w<=Math.max(0,x0))x=ax-w;
   if(inside()&&ay>y+60){
    const nh=ay-y,nw=nh*aspect;
    if(nw>=Math.min(bw,W)){w=nw;h=nh;x=clamp(centerX-w/2,0,W-w)}
    else{
     // Content runs above the tile: keep its full width and stop at the tile;
     // the composer pins this shot to the top of the stage.
     w=Math.min(W,Math.max(bw,w*.5));h=nh;x=clamp(centerX-w/2,0,W-w);
     return {...rect(x/W,y/H,w/W,h/H),fit:'top'};
    }
   }
  }
  return pinned?{...rect(x/W,y/H,w/W,h/H),fit:'top'}:rect(x/W,y/H,w/W,h/H);
 };
 // Anything wider than the shot is panned across, never silently cut off.
 if(bw>cw*1.02)return {rect:place(x0+cw/2),pan:place(x1-cw/2),zoom:stageWidth/cw};
 return {rect:place(cx),pan:null,zoom:stageWidth/cw};
}
/** Crop with the requested aspect around the same centre, for another stage size. */
export function withAspect(r,aspect,sourceWidth,sourceHeight){
 const W=sourceWidth,H=sourceHeight;
 let cw=r.w*W,ch=r.h*H;
 const cx=(r.x+r.w/2)*W,cy=(r.y+r.h/2)*H;
 if(cw/ch>aspect)ch=cw/aspect;else cw=ch*aspect;
 if(ch>H){ch=H;cw=ch*aspect}
 if(cw>W){cw=W;ch=cw/aspect}
 return rect(clamp(cx-cw/2,0,W-cw)/W,clamp(cy-ch/2,0,H-ch)/H,cw/W,ch/H);
}
const easeInOut=t=>{const x=clamp(t,0,1);return x<.5?4*x*x*x:1-Math.pow(-2*x+2,3)/2};
/** Camera rectangle at a source time. Keys move from the previous rect during [start,end]. */
export function cameraAt(track,time){
 const keys=track?.keys;if(!keys?.length||!Number.isFinite(time))return null;
 let i=-1;
 for(let lo=0,hi=keys.length-1;lo<=hi;){const m=(lo+hi)>>1;if(keys[m].start<=time){i=m;lo=m+1}else hi=m-1}
 if(i<0)return keys[0].rect;
 const k=keys[i],prev=keys[i-1];
 if(!prev||time>=k.end||k.end<=k.start)return k.rect;
 if(k.rect.fit||prev.rect.fit)return {...interpolated(prev.rect,k.rect,k,time),fit:k.rect.fit||prev.rect.fit};
 return interpolated(prev.rect,k.rect,k,time);
}
function interpolated(a,b,k,time){
 const raw=(time-k.start)/(k.end-k.start),t=k.motion==='pan'?raw:easeInOut(raw);
 // Interpolate zoom geometrically so a push-in feels uniform.
 const w=a.w*Math.pow(b.w/a.w,t),h=a.h*Math.pow(b.h/a.h,t);
 const cx=(a.x+a.w/2)+((b.x+b.w/2)-(a.x+a.w/2))*t,cy=(a.y+a.h/2)+((b.y+b.h/2)-(a.y+a.h/2))*t;
 return rect(cx-w/2,cy-h/2,w,h);
}
export function assertCameraTrack(track){
 if(!track||track.version!==2||!Array.isArray(track.keys)||!(track.source?.width>0&&track.source?.height>0))return false;
 const ok=r=>r&&[r.x,r.y,r.w,r.h].every(Number.isFinite)&&r.w>0&&r.h>0&&r.x>=-1e-6&&r.y>=-1e-6&&r.x+r.w<=1.001&&r.y+r.h<=1.001;
 if(track.speaker&&!ok(track.speaker))return false;
 let last=-Infinity;
 for(const k of track.keys){
  if(!ok(k.rect)||!Number.isFinite(k.start)||!Number.isFinite(k.end)||k.end<k.start||k.start<last)return false;
  last=k.start;
 }
 return true;
}
/**
 * Locates a webcam overlay from persistent small motion between frame pairs
 * taken ~0.4 s apart, then snaps the box to the overlay's static borders.
 * Returns null for full-frame camera footage or when nothing persistent moves.
 */
export function detectWebcam(pairs,w,h,{threshold=24,minActivity=.12}={}){
 const usable=pairs.filter(([a,b])=>{
  let changed=0;for(let i=0;i<w*h*4;i+=32)if(Math.abs(a[i]-b[i])>threshold)changed++;
  return changed/(w*h/8)<.05;
 });
 if(usable.length<4)return null;
 const activity=new Float32Array(w*h),mean=new Float32Array(w*h);
 for(const [a,b] of usable)for(let i=0;i<w*h;i++){
  const k=i*4;
  if(Math.max(Math.abs(a[k]-b[k]),Math.abs(a[k+1]-b[k+1]),Math.abs(a[k+2]-b[k+2]))>threshold)activity[i]++;
  mean[i]+=(a[k]*.3+a[k+1]*.59+a[k+2]*.11)/usable.length;
 }
 const active=new Uint8Array(w*h);let total=0;
 for(let i=0;i<w*h;i++)if(activity[i]/usable.length>=minActivity){active[i]=1;total++}
 if(total<w*h*.001||total>w*h*.25)return null;
 const {labels,comps}=label(dilate(active,w,h,3,3),w,h,true);
 const score=new Float64Array(comps.length+1);
 for(let i=0;i<w*h;i++)if(active[i])score[labels[i]]+=activity[i];
 let best=null;for(const c of comps)if(!best||score[c.id]>score[best.id])best=c;
 if(!best)return null;
 let {x0,y0,x1,y1}=best;
 // Static border of the overlay: strongest straight edge in the averaged frame.
 const edge=(fixed,from,to,horizontal)=>{
  let hits=0,n=0;
  for(let t=from;t<=to;t++){
   const a=horizontal?mean[fixed*w+t]:mean[t*w+fixed],b=horizontal?mean[(fixed-1)*w+t]:mean[t*w+fixed-1];
   n++;if(Math.abs(a-b)>18)hits++;
  }
  return n?hits/n:0;
 };
 const reachX=Math.round((x1-x0+1)*.6),reachY=Math.round((y1-y0+1)*.6);
 const snap=(start,lo,hi,score)=>{
  let pick=start,top=.55;
  for(let p=lo;p<=hi;p++){const s=score(p);if(s>top){top=s;pick=p}}
  return {pick,found:top>.55};
 };
 const left=x0<=2?{pick:0,found:true}:snap(x0,Math.max(1,x0-reachX),x0,p=>edge(p,y0,y1,false));
 const right=x1>=w-3?{pick:w,found:true}:snap(x1,x1+1,Math.min(w-1,x1+reachX),p=>edge(p,y0,y1,false));
 const top=y0<=2?{pick:0,found:true}:snap(y0,Math.max(1,y0-reachY),y0,p=>edge(p,x0,x1,true));
 const bottom=y1>=h-3?{pick:h,found:true}:snap(y1,y1+1,Math.min(h-1,y1+reachY),p=>edge(p,x0,x1,true));
 // Call tiles sit in a corner: an edge not found near the frame border runs to it.
 const near=(gap,size)=>gap<size*.08;
 const bx0=left.found?left.pick:near(x0,w)?0:Math.max(0,x0-4);
 const bx1=right.found?right.pick:near(w-1-x1,w)?w:Math.min(w,x1+5);
 let by0=top.found?top.pick:Math.max(0,y0-4);
 const by1=bottom.found?bottom.pick:near(h-1-y1,h)?h:Math.min(h,y1+5);
 // Motion covers the face and shoulders, not the tile: complete a too-flat box to a call-tile shape.
 if(!top.found&&(bx1-bx0)/(by1-by0)>2)by0=Math.max(0,Math.round(by1-(bx1-bx0)/1.78));
 const box=rect(bx0/w,by0/h,(bx1-bx0)/w,(by1-by0)/h);
 if(area(box)>.3)return null;
 // Inset by a pixel so the overlay's own frame line is not drawn.
 const ix=1.5/w,iy=1.5/h;
 return {box:rect(box.x+ix,box.y+iy,Math.max(ix,box.w-2*ix),Math.max(iy,box.h-2*iy)),
  confidence:Math.min(1,score[best.id]/usable.length/Math.max(1,best.count)),edges:[left,right,top,bottom].filter(e=>e.found).length};
}
const MIN_HOLD=1.6,MOVE=.75,DWELL=6;
/**
 * Streaming indexer: push analysis frames in source-time order, then finish().
 * State changes (new slide) produce cuts; local changes (a revealed bullet,
 * typed code, an annotation) move the camera to the block that changed;
 * without changes the camera dwells on blocks in reading order.
 */
export function createCameraIndexer({width,height,sourceWidth,sourceHeight,speaker=null,
  aspect=null,stageWidth=STAGE.w}={}){
 // Plan for the stage the composer will actually draw (it depends on the webcam shape).
 aspect=aspect||cameraStageAspect(speaker?(speaker.w*sourceWidth)/(speaker.h*sourceHeight):null,{speaker:!!speaker});
 if(!(width>0&&height>0&&sourceWidth>0&&sourceHeight>0))throw Error('Invalid camera indexer dimensions');
 // Conference tiles grow or are replaced (another speaker during Q&A): keep a
 // generous zone around the presenter out of content and change analysis.
 const zone=speaker&&rect(Math.max(0,speaker.x-speaker.w*.5),Math.max(0,speaker.y-speaker.h*.5),
  speaker.w*2,speaker.h*2);
 const exclude=zone?[zone]:[];
 const states=[];let prev=null,state=null,pendingBlocks=false;
 const avoid=speaker&&rect(Math.max(0,speaker.x-.015),Math.max(0,speaker.y-.02),speaker.w+.03,speaker.h+.04);
 const frameOpts={sourceWidth,sourceHeight,aspect,stageWidth,avoid};
 const blocksOf=rgba=>contentBlocks(rgba,width,height,{exclude});
 function open(time,rgba,stable){
  state={start:time,end:time,blocks:blocksOf(rgba),events:[]};states.push(state);pendingBlocks=!stable;
 }
 return {
  push(time,rgba){
   if(rgba.length!==width*height*4)throw Error('Mismatched analysis frame');
   if(!prev){open(time,rgba,true);prev=rgba;return}
   const change=changeRegion(prev,rgba,width,height,{exclude});
   state.end=time;
   const wide=change.box&&area(change.box)>.45;
   if(change.fraction>.2||(wide&&change.fraction>.06))open(time,rgba,false);
   else if(pendingBlocks&&change.fraction<.01){state.blocks=blocksOf(rgba);pendingBlocks=false}
   else if(change.box&&change.fraction>.00035)state.events.push({time,box:change.box,blocks:blocksOf(rgba)});
   prev=rgba;
  },
  /** Discontinuity (e.g. next EDL range): the next frame opens a new state. */
  cut(){prev=null},
  finish(duration){
   if(state&&Number.isFinite(duration))state.end=Math.max(state.end,duration);
   return {version:2,source:{width:sourceWidth,height:sourceHeight},speaker,
    stage:{aspect},keys:planKeys(states,frameOpts),method:'pixel-reveal-camera'};
  }
 };
}
function targetFor(event){
 const center={x:event.box.x+event.box.w/2,y:event.box.y+event.box.h/2};
 const hit=event.blocks.find(b=>center.x>=b.x&&center.x<=b.x+b.w&&center.y>=b.y&&center.y<=b.y+b.h)||
  event.blocks.map(b=>({b,o:overlap(b,event.box)})).sort((a,b)=>b.o-a.o).find(x=>x.o>0)?.b;
 if(hit)return hit;
 // A pointer flicker or codec noise outside any content is not a focus cue.
 return area(event.box)>=.004?event.box:null;
}
function mergeEvents(events){
 const out=[];
 for(const e of events){
  const last=out.at(-1);
  if(last&&e.time-last.time<1.6){last.box=union([last.box,e.box]);last.blocks=e.blocks;last.time=e.time;}
  else out.push({...e});
 }
 return out;
}
function groupBlocks(blocks,count){
 if(blocks.length<=count)return blocks;
 const size=Math.ceil(blocks.length/count),out=[];
 for(let i=0;i<blocks.length;i+=size)out.push(union(blocks.slice(i,i+size)));
 return out;
}
const signature=b=>[b.x,b.y,b.w,b.h].map(v=>Math.round(v*50)).join(':');
/** Blocks repeated at the same place on many slides are template chrome (buttons, logos). */
export function dropTemplateBlocks(states){
 const seen=new Map();
 for(const s of states){
  const keys=new Set([...s.blocks,...s.events.flatMap(e=>e.blocks)].map(signature));
  for(const k of keys)seen.set(k,(seen.get(k)||0)+1);
 }
 const limit=Math.max(3,states.length*.25);
 const keep=b=>(seen.get(signature(b))||0)<limit;
 for(const s of states){
  s.blocks=s.blocks.filter(keep);
  for(const e of s.events)e.blocks=e.blocks.filter(keep);
 }
 return states;
}
function planKeys(states,opts){
 dropTemplateBlocks(states);
 const keys=[];
 const add=(start,r,{cut=false,until=null,motion='move'}={})=>{
  const last=keys.at(-1);
  if(last&&iou(last.rect,r)>.9)return;
  if(last&&!cut)start=Math.max(start,last.end+MIN_HOLD*(last.motion==='pan'?0:1));
  if(last&&start<last.start)start=last.start;
  const end=cut?start:until??start+MOVE;
  keys.push({start,end:Math.max(start,end),rect:r,motion:cut?'cut':motion});
 };
 let shown=null;
 const show=(start,end,box,first)=>{
  // Another change inside the block already on screen keeps the current shot,
  // unless the reveal widened the content beyond it.
  const last=keys.at(-1)?.rect;
  const fits=last&&box.x>=last.x-.005&&box.x+box.w<=last.x+last.w+.005&&box.y+box.h<=last.y+last.h+.005;
  if(!first&&shown&&iou(shown,box)>.75&&fits)return;
  shown=box;
  const f=frameContent(box,opts);
  add(start,f.rect,{cut:first});
  if(f.pan&&end-start>=5)add(start+Math.min(2,(end-start)*.25),f.pan,{until:end-.8,motion:'pan'});
 };
 for(const s of states){
  const events=mergeEvents(s.events);
  const firstEvent=events[0]?.time??s.end;
  const blocks=s.blocks.length?s.blocks:null;
  if(blocks){
   const whole=union(blocks),overview=frameContent(whole,opts);
   const span=firstEvent-s.start;
   if(blocks.length===1||(overview.zoom>=1&&!overview.pan))show(s.start,firstEvent,whole,true);
   else{
    const parts=groupBlocks(blocks,Math.max(1,Math.floor(span/DWELL)));
    const share=span/parts.length;
    parts.forEach((b,i)=>show(s.start+i*share,s.start+(i+1)*share,b,i===0));
   }
  }else if(!keys.length)add(s.start,withAspect(rect(0,0,1,1),opts.aspect,opts.sourceWidth,opts.sourceHeight),{cut:true});
  events.forEach((e,i)=>{const target=targetFor(e);if(target)show(e.time,events[i+1]?.time??s.end,target,false)});
 }
 return keys;
}
