/** Source-grounded spatial semantics for teaching slides and software UI.
 * No generative claims. OCR text is evidence; uncertain diagrams stay as original pixels.
 */
const limit=(x,a,b)=>Math.max(a,Math.min(b,x));
const words=s=>String(s||'').toLowerCase().match(/[\p{L}\p{N}]{3,}/gu)||[];
const rectOK=b=>b&&[b.x0,b.y0,b.x1,b.y1].every(Number.isFinite)&&b.x1>b.x0&&b.y1>b.y0;
const center=b=>({x:(b.x0+b.x1)/2,y:(b.y0+b.y1)/2});
const overlapRatio=(a,b)=>{
  const w=Math.max(0,Math.min(a.x1,b.x1)-Math.max(a.x0,b.x0));
  const h=Math.max(0,Math.min(a.y1,b.y1)-Math.max(a.y0,b.y0));
  return w*h/Math.max(1,(a.x1-a.x0)*(a.y1-a.y0));
};
export function sourceEvidence(lines,width,height,{speaker=null}={}){
 const sp=speaker?{x0:speaker.x*width,y0:speaker.y*height,
   x1:(speaker.x+speaker.w)*width,y1:(speaker.y+speaker.h)*height}:null;
 return (lines||[]).filter(l=>l&&rectOK(l.box)&&Number.isFinite(l.confidence)&&l.confidence>=30)
  .filter(l=>l.box.x0>=0&&l.box.y0>=0&&l.box.x1<=width+2&&l.box.y1<=height+2)
  .filter(l=>!sp||overlapRatio(l.box,sp)<.6)
  .map(l=>({...l,text:String(l.text||'').trim().slice(0,300)})).filter(l=>l.text);
}
function robustSample(sampleRgb,x,y,width,height){
 if(typeof sampleRgb!=='function')return null;
 const p=sampleRgb(limit(Math.floor(x),0,width-1),limit(Math.floor(y),0,height-1));
 return Array.isArray(p)&&p.length>=3&&p.every((v,i)=>i>2||Number.isFinite(v))?p:null;
}
function colorSignal(p){
 if(!p)return 0;
 const [r,g,b]=p;
 // Distinguish lightly blue selected tab background from neutral white/grey;
 // not guaranteed for arbitrary themes. Never infer it solely from the text.
 return limit((b-r-8)/42,0,1)*.7+limit((b-g-6)/42,0,1)*.3;
}
export function selectedTabFromPixels(tabs,sampleRgb,width,height){
 const measured=tabs.map(tab=>{
  const b=tab.box;
  const dx=Math.max(12,Math.round((b.x1-b.x0)*.10));
  const dy=Math.max(5,Math.round((b.y1-b.y0)*.12));
  const probes=[
    robustSample(sampleRgb,b.x0-dx,(b.y0+b.y1)/2,width,height),
    robustSample(sampleRgb,b.x0-dx,b.y0-dy,width,height),
    robustSample(sampleRgb,b.x1+dx,(b.y0+b.y1)/2,width,height)
  ].filter(Boolean);
  const signal=probes.length?probes.reduce((s,p)=>s+colorSignal(p),0)/probes.length:0;
  return {...tab,visualSelectionScore:signal};
 });
 const highest=Math.max(...measured.map(t=>t.visualSelectionScore));
 const runnerUp=[...measured.map(t=>t.visualSelectionScore)].sort((a,b)=>b-a)[1]||0;
 const distinct=highest>.28&&highest-runnerUp>.16;
 return measured.map(t=>({...t,active:distinct&&t.visualSelectionScore===highest}));
}
export function analyzeSlideContext(lines,width,height,{speaker=null,sampleRgb=null}={}){
 if(!(width>0&&height>0))throw Error('Invalid video dimensions');
 const valid=sourceEvidence(lines,width,height,{speaker});
 const brand=valid.filter(l=>l.box.y0<height*.18&&l.box.x0>width*.74&&l.text.length<=24);
 const slideLines=valid.filter(l=>!brand.includes(l));
 const headings=slideLines.filter(l=>l.box.y0<height*.19&&l.box.x0<width*.72&&l.text.length>=4)
  .sort((a,b)=>a.box.y0-b.box.y0||a.box.x0-b.box.x0);
 const title=headings.slice(0,2).map(l=>l.text).join(' ').slice(0,150);
 const candidate=slideLines.filter(l=>{
   const b=l.box,c=center(b);return c.y>=height*.14&&c.y<=height*.52&&
    b.x1-b.x0<width*.35&&l.text.length>=3&&l.text.length<=38&&
    !headings.includes(l);
 });
 // Navigation tabs are a horizontal set of 3+ similarly aligned short labels.
 const bands=[];
 for(const item of candidate){
   const lane=bands.find(b=>Math.abs(b.y-center(item.box).y)<Math.max(24,height*.035));
   if(lane)lane.items.push(item);
   else bands.push({y:center(item.box).y,items:[item]});
 }
 const nav=bands.map(b=>b.items.sort((a,b)=>a.box.x0-b.box.x0))
   .filter(arr=>arr.length>=3&&arr.length<=7&&new Set(arr.map(l=>l.text.toLowerCase())).size===arr.length)
   .sort((a,b)=>b.length-a.length)[0]||[];
 let tabs=nav.map((l,i)=>({text:l.text,box:l.box,index:i,confidence:l.confidence}));
 if(tabs.length)tabs=selectedTabFromPixels(tabs,sampleRgb,width,height);
 const navSet=new Set(nav);
 const elems=slideLines.filter(l=>!headings.includes(l)&&!navSet.has(l)).map(l=>{
   const s=l.text,tech=/\b(?:import |from |class |def |const |function |docker\s+(?:build|run)|FROM |RUN |COPY )/i.test(s);
   const math=/[∫∑√π≈≤≥=]|\\frac|\\alpha|\b(?:sin|cos|log)\(/i.test(s);
   return {kind:tech?'code':math?'formula':'text',text:s,box:l.box,confidence:l.confidence};
 });
 const textEvidence=slideLines.map(l=>l.text);
 return {
  version:1,
  kind:tabs.length?'software-ui':elems.some(e=>e.kind==='code')?'code-or-terminal':'lecture-slide',
  title,brandText:brand.map(l=>l.text),
  tabs,activeTab:tabs.find(t=>t.active)?.text||null,
  elements:elems,
  originalPixelRequired:true,
  recognizedText:textEvidence,
  caveats:['OCR does not prove diagram semantics','Unknown or ambiguous symbols remain source pixels']
 };
}
export function speechTarget(context,spoken=''){
 const speech=new Set(words(spoken));
 const items=[...(context?.tabs||[]).map(t=>({type:'tab',text:t.text,box:t.box})),
   ...(context?.elements||[]).map(x=>({type:x.kind,text:x.text,box:x.box}))];
 const scores=items.map((e,i)=>({
  index:i,item:e,
  score:words(e.text).reduce((s,w)=>s+(speech.has(w)?1:0),0)
 }));
 scores.sort((a,b)=>b.score-a.score);
 return scores[0]?.score>0?{...scores[0].item,matchedTokens:scores[0].score}:null;
}
