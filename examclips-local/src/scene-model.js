// Scene plan v2. Coordinates are normalized to the SOURCE frame.
// Geometry and layout functions are pure, deterministic, and unit-testable.
const clamp=(n,a,b)=>Math.min(b,Math.max(a,n));
const rect=(x,y,w,h)=>({x,y,w,h});
export function sourceRect(r,w,h){
  const x=clamp(Math.round(r.x*w),0,w-1),y=clamp(Math.round(r.y*h),0,h-1);
  return {x,y,w:Math.max(1,Math.min(w-x,Math.round(r.w*w))),h:Math.max(1,Math.min(h-y,Math.round(r.h*h)))};
}
export function flattenOcr(blocks=[]){
  const out=[];
  for(const b of blocks||[])for(const p of b.paragraphs||[])for(const l of p.lines||[]){
    const words=l.words||[];
    if(words.length===0)continue;
    const text=words.map(w=>w.text||'').join(' ').trim();
    if(!text)continue;
    const confidence=words.reduce((s,w)=>s+(Number(w.confidence)||0),0)/words.length;
    out.push({text,box:l.bbox||p.bbox||b.bbox,confidence});
  }
  return out;
}
export function layoutFromOcr(lines=[],width=1600,height=900){
  const title=lines.filter(l=>l.box&&l.box.y0<height*.17&&l.confidence>=55)
    .sort((a,b)=>a.box.y0-b.box.y0).map(l=>l.text.trim()).filter(Boolean).slice(0,2).join(' ').slice(0,95);
  const body=lines.filter(l=>l.box&&l.box.y0>=height*.16&&l.box.y0<height*.85&&l.box.x0<width*.99&&l.confidence>=35);
  const left=body.filter(l=>((l.box.x0+l.box.x1)/2)<width*.59);
  const right=body.filter(l=>((l.box.x0+l.box.x1)/2)>=width*.59);
  const anyLeft=left.length>0,anyRight=right.length>0;
  // Never assume OCR captured non-text graphics. First version ALWAYS retains source image crops.
  // Real slides may have large images even when OCR sees no text.
  const panels=[
    {id:'left',label:'Основная часть',rect:rect(.035,.165,.555,.685),text:left.map(l=>l.text).join(' ').slice(0,900)},
    {id:'right',label:'Пояснения',rect:rect(.59,.165,.375,.685),text:right.map(l=>l.text).join(' ').slice(0,900)}
  ];
  if(!anyLeft&&!anyRight)return {title:'',panels,hasOcr:false};
  return {title,panels,hasOcr:true};
}
export function tokens(text=''){return [...new Set((text.toLowerCase().match(/[\p{L}\p{N}]{4,}/gu)||[]).filter(x=>x.length>3))]}
export function focusForSpeech(panels,spoken='',fallback=0){
  const speech=tokens(spoken);
  const scores=panels.map(p=>{
    const words=tokens(p.text||'');
    const content=new Set(words);return speech.filter(t=>content.has(t)).length;
  });
  const best=Math.max(...scores);
  if(best===0)return fallback%panels.length;
  return scores.indexOf(best);
}
export function makeStoryboard({width,height,lines=[],duration=90,chunks=[],speaker=null,titleOverride='' }){
  if(!(width>0&&height>0&&duration>0))throw Error('Invalid scene dimensions or duration');
  const layout=layoutFromOcr(lines,width,height);
  const panels=layout.panels;
  const beats=[];
  const count=Math.min(40,Math.max(1,Math.ceil(duration/9)));
  let previous=-1;
  for(let i=0;i<count;i++){
    const a=i*duration/count,b=(i+1)*duration/count;
    const spoken=chunks.filter(c=>c.end>a&&c.start<b).map(c=>c.text).join(' ');
    const target=focusForSpeech(panels,spoken,i);
    const focus=target===previous&&panels.length>1&&!spoken.trim()?((target+1)%panels.length):target;
    beats.push({time:a,focus});previous=focus;
  }
  return {version:2,title:titleOverride||layout.title,panels,beats,speaker:speaker||rect(.815,.854,.18,.14),
    method:layout.hasOcr?'ocr-assisted-original-crops':'pixel-preserving-split',
    source:{width,height}};
}
export function sceneAt(scene,elapsed){let current=scene.beats[0]||{time:0,focus:0};for(const b of scene.beats){if(b.time>elapsed)break;current=b}return current}
export function assertScene(scene){
  if(!scene||scene.version!==2||!Array.isArray(scene.panels)||scene.panels.length===0||!Array.isArray(scene.beats))return false;
  return [...scene.panels.map(p=>p.rect),scene.speaker].every(r=>r&&[r.x,r.y,r.w,r.h].every(Number.isFinite)&&r.x>=0&&r.y>=0&&r.w>0&&r.h>0&&r.x+r.w<=1.001&&r.y+r.h<=1.001);
}
