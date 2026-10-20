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
  const paddedRect=(items,fallback)=>{
    if(items.length<3)return fallback;
    const x0=Math.min(...items.map(l=>l.box.x0)),x1=Math.max(...items.map(l=>l.box.x1));
    const y0=Math.min(...items.map(l=>l.box.y0)),y1=Math.max(...items.map(l=>l.box.y1));
    const padX=width*.035,padY=height*.06;
    const leftX=clamp(x0-padX,0,width-1),upperY=clamp(y0-padY,0,height-1);
    return rect(leftX/width,upperY/height,
      Math.min(width-leftX,x1-x0+2*padX)/width,
      Math.min(height-upperY,y1-y0+2*padY)/height);
  };
  // Never assume OCR captured non-text graphics. First version ALWAYS retains source image crops.
  // Real slides may have large images even when OCR sees no text.
  const panels=[
    {id:'left',label:'Основная часть',rect:paddedRect(left,rect(.035,.165,.555,.685)),
       text:left.map(l=>l.text).join(' ').slice(0,900),lines:left.filter(l=>l.confidence>=75).map(l=>l.text).slice(0,24)},
    {id:'right',label:'Пояснения',rect:paddedRect(right,rect(.59,.165,.375,.685)),
       text:right.map(l=>l.text).join(' ').slice(0,900),lines:right.filter(l=>l.confidence>=75).map(l=>l.text).slice(0,24)}
  ];
  if(!anyLeft&&!anyRight)return {title:'',panels:[{id:'source',label:'Материал лекции',rect:rect(.02,.16,.96,.68),lines:[],sourceOnly:true}],hasOcr:false};
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
// Sparse edge scan: locate real source content without OCR or neural inference.
export function pixelPanels(pixels,width,height){
 if(!pixels||pixels.length!==width*height*4)return null;
 const step=Math.max(1,Math.floor(width/400)),out=[];
 for(const [side,lo,hi] of [[0,.02,.5],[1,.5,.98]]){
  let x0=width,y0=height,x1=0,y1=0,hits=0;
  for(let y=Math.floor(height*.17);y<height*.82-step;y+=step)
   for(let x=Math.floor(width*lo);x<width*hi-step;x+=step){
    const at=(y*width+x)*4,right=at+step*4,below=at+step*width*4;
    const difference=Math.max(...[0,1,2].map(c=>Math.max(Math.abs(pixels[at+c]-pixels[right+c]),Math.abs(pixels[at+c]-pixels[below+c]))));
    if(difference<35)continue;
    hits++;x0=Math.min(x0,x);x1=Math.max(x1,x+step);y0=Math.min(y0,y);y1=Math.max(y1,y+step);
   }
  if(hits<12)continue;
  const x=Math.max(0,x0/width-.025),y=Math.max(.15,y0/height-.035);
  out.push({side,rect:rect(x,y,Math.min(1-x,(x1-x0)/width+.05),Math.min(.84-y,(y1-y0)/height+.07))});
 }
 return out;
}
export function makeStoryboard({width,height,lines=[],duration=90,chunks=[],speaker=null,titleOverride='',pixels=null }){
  if(!(width>0&&height>0&&duration>0))throw Error('Invalid scene dimensions or duration');
  const layout=layoutFromOcr(lines,width,height);
  let panels=layout.panels;
  const observed=pixelPanels(pixels,width,height);
  if(observed?.length){
    panels=observed.map(({side,rect:r})=>{
      const matching=lines.filter(l=>l.box&&l.box.y0>=height*.17&&l.box.y0<height*.82&&((l.box.x0+l.box.x1)/2>=width*.5?1:0)===side);
      // Include entire OCR boxes even when a line crosses the partition.
      const technical=matching.length>=2&&matching.some(l=>/\b(?:docker\s+(?:run|network|build)|FROM\s|WORKDIR|npm\s|COPY\s|RUN\s)/u.test(l.text));
      if(technical){
        const left=Math.max(0,Math.min(...matching.map(l=>l.box.x0))/width-.025);
        const top=Math.max(.15,Math.min(...matching.map(l=>l.box.y0))/height-.035);
        const right=Math.min(1,Math.max(...matching.map(l=>l.box.x1))/width+.025);
        const bottom=Math.min(.84,Math.max(...matching.map(l=>l.box.y1))/height+.035);
        // OCR can miss the end of a command. Never shrink horizontal pixel evidence.
        const safeLeft=Math.min(r.x,left),safeRight=Math.max(r.x+r.w,right);
        const code=matching.some(l=>/^\s*(?:FROM|WORKDIR|RUN|COPY|CMD|EXPOSE)\s/u.test(l.text));
        const safeTop=code?Math.min(r.y,top):top,safeBottom=code?Math.max(r.y+r.h,bottom):bottom;
        r={x:safeLeft,y:safeTop,w:safeRight-safeLeft,h:safeBottom-safeTop};
      }
      const x=Math.min(r.x,...matching.map(l=>l.box.x0/width)),right=Math.max(r.x+r.w,...matching.map(l=>l.box.x1/width));
      return {id:side?'right':'left',label:side?'Пояснения':'Основная часть',rect:{...r,x,w:Math.min(1,right)-x},
        text:matching.map(l=>l.text).join(' '),lines:matching.filter(l=>l.confidence>=75).map(l=>l.text),sourceOnly:true};
    });
  }
  // A long OCR line can expand one panel across the partition. Drop a smaller
  // region already contained in that source view instead of magnifying its tail.
  panels=panels.filter((panel,index)=>!panels.some((other,j)=>{
    if(index===j)return false;
    const a=panel.rect,b=other.rect,area=a.w*a.h;
    const overlap=Math.max(0,Math.min(a.x+a.w,b.x+b.w)-Math.max(a.x,b.x))*
      Math.max(0,Math.min(a.y+a.h,b.y+b.h)-Math.max(a.y,b.y));
    return b.w*b.h>area*1.5&&overlap>=area*.95;
  }));
  const beats=[];
  const count=Math.min(40,Math.max(1,Math.ceil(duration/9)));
  let previous=-1;
  for(let i=0;i<count;i++){
    const a=i*duration/count,b=(i+1)*duration/count;
    const spoken=chunks.filter(c=>c.end>a&&c.start<b).map(c=>c.text).join(' ');
    const target=focusForSpeech(panels,spoken,previous<0?Math.max(0,panels.findIndex(p=>p.text?.trim())):previous);
    const focus=target;
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
