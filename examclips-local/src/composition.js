import {makeStoryboard,sourceRect,assertScene} from './scene-model.js';
import {editorialTimeline,editorialGeometry,fitTypography,suitableOcrLines,paletteFor} from './editorial-motion.js';
export const WIDTH=720,HEIGHT=1280;
function lineWrap(ctx,text,maxWidth){
  const words=text.trim().split(/\s+/),lines=[],current={v:''};
  for(const w of words){const next=(current.v?current.v+' ':'')+w;
    if(ctx.measureText(next).width>maxWidth&&current.v){lines.push(current.v);current.v=w}else current.v=next}
  if(current.v)lines.push(current.v);return lines.slice(0,4);
}
export function paintFrame(canvas,source,width,height,layout,focusX,subtitle='',scene=null,elapsed=0){
  if(layout==='hybrid')return paintHybrid(canvas,source,width,height,subtitle,scene,elapsed);
  const ctx=canvas.getContext('2d'),cw=canvas.width,ch=canvas.height;
  ctx.fillStyle='#09111f';ctx.fillRect(0,0,cw,ch);
  const draw=(sx,sy,sw,sh,dx,dy,dw,dh)=>{
    if(typeof source.draw==='function')source.draw(ctx,sx,sy,sw,sh,dx,dy,dw,dh);
    else ctx.drawImage(source,sx,sy,sw,sh,dx,dy,dw,dh);
  };
  if(layout==='crop'){
    const cropW=Math.min(width,height*cw/ch),sx=(width-cropW)*Math.max(0,Math.min(100,focusX))/100;
    draw(sx,0,cropW,height,0,0,cw,ch);
  }else if(layout==='focus'){
    const dh=ch*.73,cropW=Math.min(width,height*cw/dh),sx=(width-cropW)*Math.max(0,Math.min(100,focusX))/100;
    draw(sx,0,cropW,height,0,Math.round(ch*.08),cw,dh);
  }else{
    // Fit deliberately preserves the COMPLETE original frame; never silently crop formulae.
    const scale=Math.min(cw/width,(ch*.72)/height),dw=width*scale,dh=height*scale;
    draw(0,0,width,height,(cw-dw)/2,(ch*.72-dh)/2+ch*.05,dw,dh);
  }
  const grad=ctx.createLinearGradient(0,ch*.69,0,ch);grad.addColorStop(0,'#09111f00');grad.addColorStop(1,'#09111fee');
  ctx.fillStyle=grad;ctx.fillRect(0,ch*.69,cw,ch*.31);
  if(subtitle.trim()){
    ctx.textAlign='center';ctx.font='bold 35px system-ui, sans-serif';
    const lines=lineWrap(ctx,subtitle,cw-80);
    const y=ch-100-(lines.length-1)*46;
    lines.forEach((line,i)=>{ctx.lineWidth=8;ctx.strokeStyle='#050a14';ctx.strokeText(line,cw/2,y+i*46);ctx.fillStyle='#fff';ctx.fillText(line,cw/2,y+i*46)});
  }
}


// Editorial motion layout: deterministic, responsive and independent of Remotion runtime.
// Drawing works on both HTMLVideoElement (preview) and VideoSample (export).
function roundBox(ctx,x,y,w,h,r=20){ctx.beginPath();ctx.roundRect(x,y,w,h,r);ctx.closePath()}
function crop(ctx,src,r,dx,dy,dw,dh,sw,sh,cover=false){
 const rect=sourceRect(r,sw,sh);
 if(cover){
   const aspect=dw/dh,sourceAspect=rect.w/rect.h;
   if(sourceAspect>aspect){
      const nw=rect.h*aspect;
      rect.x+=(rect.w-nw)/2;rect.w=nw;
   }else{
      const nh=rect.w/aspect;
      rect.y+=(rect.h-nh)/2;rect.h=nh;
   }
 }
 const scale=Math.min(dw/rect.w,dh/rect.h);
 const nw=rect.w*scale,nh=rect.h*scale;
 const tx=dx+(dw-nw)/2,ty=dy+(dh-nh)/2;
 if(typeof src.draw==='function')src.draw(ctx,rect.x,rect.y,rect.w,rect.h,tx,ty,nw,nh);
 else ctx.drawImage(src,rect.x,rect.y,rect.w,rect.h,tx,ty,nw,nh);
}
function roundedSurface(ctx,rect,color,radius=24,border=null){
 ctx.fillStyle=color;roundBox(ctx,rect.x,rect.y,rect.w,rect.h,radius);ctx.fill();
 if(border){ctx.strokeStyle=border;ctx.lineWidth=1.5;ctx.stroke()}
}
function label(ctx,text,x,y,{color='#59677C',fontSize=18,weight=700,letterSpacing=0}={}){
 ctx.save();ctx.textAlign='left';ctx.textBaseline='alphabetic';
 ctx.font=weight+' '+fontSize+'px system-ui, sans-serif';
 ctx.fillStyle=color;ctx.fillText(text,x,y);ctx.restore();
}
function drawText(ctx,text,x,y,box,palette,kind='body'){
 const opts=kind==='title'
   ? {maxFont:57,minFont:34,maxLines:2,weight:740,lineHeight:1.05}
   : {maxFont:36,minFont:25,maxLines:7,weight:580,lineHeight:1.27};
 const result=fitTypography(ctx,text,{width:box.w,height:box.h,...opts});
 ctx.save();ctx.font=opts.weight+' '+result.size+'px system-ui, sans-serif';
 ctx.fillStyle=palette.ink;ctx.textBaseline='top';ctx.textAlign='left';
 for(let i=0;i<result.lines.length;i++)ctx.fillText(result.lines[i],x,y+i*result.lineHeight);
 ctx.restore();return result;
}
function renderEditorialPanel(ctx,src,sw,sh,panel,stage,palette,{opacity=1,rise=0,reveal=1}={}){
 if(!panel||opacity<=0)return;
 ctx.save();
 ctx.globalAlpha=opacity;
 ctx.translate(0,rise);
 ctx.beginPath();roundBox(ctx,stage.x,stage.y,stage.w,stage.h,25);ctx.clip();
 ctx.fillStyle=palette.surface;ctx.fillRect(stage.x,stage.y,stage.w,stage.h);
 const sourceRectArea={x:stage.x+18,y:stage.y+17,w:stage.w-36,h:stage.h-34};
 const lines=suitableOcrLines(panel);
 const rich=lines.length>=3&&lines.join(' ').length>70;
 if(rich){
   const x=stage.x+40,textWidth=stage.w-80;
   ctx.fillStyle=palette.accent;roundBox(ctx,x,stage.y+42,60,7,3);ctx.fill();
   label(ctx,panel.label||'ОСНОВНОЕ',x,stage.y+104,{color:palette.muted,fontSize:21,weight:650});
   // Progressive disclosure: one new verified OCR line at a time, no invented facts.
   const revealCount=Math.min(lines.length,Math.max(1,Math.ceil(reveal*lines.length)));
   let yy=stage.y+144;
   for(let index=0;index<revealCount;index++){
      const remaining=stage.y+stage.h-42-yy;
      if(remaining<52)break;
      const text=lines[index];
      const metrics=fitTypography(ctx,text,{width:textWidth-34,height:Math.min(remaining,130),
        maxFont:35,minFont:23,maxLines:3,lineHeight:1.18,weight:560});
      const blockH=metrics.lines.length*metrics.lineHeight;
      ctx.fillStyle=palette.accentSurface;roundBox(ctx,x,yy+11,9,9,4);ctx.fill();
      ctx.font='560 '+metrics.size+'px system-ui, sans-serif';
      ctx.textBaseline='top';ctx.textAlign='left';ctx.fillStyle=palette.ink;
      for(let k=0;k<metrics.lines.length;k++)ctx.fillText(metrics.lines[k],x+30,yy+k*metrics.lineHeight);
      yy+=Math.max(52,blockH+25);
   }
 }else{
   // Keep real visual diagram pixels; OCR is not permitted to make up a mathematical relation.
   roundedSurface(ctx,sourceRectArea,palette.panel,17);
   ctx.save();roundBox(ctx,sourceRectArea.x,sourceRectArea.y,sourceRectArea.w,sourceRectArea.h,17);ctx.clip();
   const inset=16;
   crop(ctx,src,panel.rect,sourceRectArea.x+inset,sourceRectArea.y+inset,
     sourceRectArea.w-inset*2,sourceRectArea.h-inset*2,sw,sh);
   ctx.restore();
 }
 ctx.restore();
}
export function paintHybrid(canvas,src,sw,sh,subtitle='',scene=null,elapsed=0){
 const ctx=canvas.getContext('2d'),width=canvas.width,height=canvas.height;
 const chapter=scene?.chapters?.findLast(item=>item.start<=elapsed)||null;
 const spec=assertScene(chapter?.scene)?chapter.scene:
   (assertScene(scene)?scene:makeStoryboard({width:sw,height:sh,duration:90}));
 const t=Math.max(0,elapsed-(chapter?.start||0));
 const director=editorialTimeline(spec,t);
 const theme=scene?.theme||spec.theme||'warm';
 const p=paletteFor(theme),g=editorialGeometry(width,height,{speaker:!spec.hideSpeaker});
 const s=width/720;
 ctx.save();
 ctx.clearRect(0,0,width,height);
 ctx.fillStyle=p.background;ctx.fillRect(0,0,width,height);
 // Quiet, magazine-style typography: no redundant screenshot of the original slide title.
 label(ctx,'УЧЕБНЫЙ РАЗБОР',g.eyebrow.x,g.eyebrow.y+21*s,{color:p.accent,fontSize:17*s,weight:820});
 const total=spec.panels.length;
 ctx.textAlign='right';ctx.font='650 '+(18*s)+'px system-ui, sans-serif';
 ctx.fillStyle=p.muted;ctx.fillText(String(director.current+1).padStart(2,'0')+' / '+String(total).padStart(2,'0'),width-42*s,64*height/1280);
 const title=(spec.title||scene?.title||'Материал лекции').replace(/\s+/g,' ').trim();
 drawText(ctx,title,g.title.x,g.title.y,g.title,p,'title');
 // Course material is the hero. Content switches only on a semantic/timed beat.
 roundedSurface(ctx,g.stage,p.surface,25*width/720,p.line);
 const currentPanel=spec.panels[director.current]||spec.panels[0];
 if(director.mix<1){
   const oldPanel=spec.panels[director.previous]||currentPanel;
   renderEditorialPanel(ctx,src,sw,sh,oldPanel,g.stage,p,{opacity:1-director.mix});
 }
 renderEditorialPanel(ctx,src,sw,sh,currentPanel,g.stage,p,{
    opacity:director.mix,rise:(1-director.progress)*12*height/1280,reveal:Math.min(1,.35+t/9)
 });
 // Minimal stage navigation; no pasted OCR text and no duplicate badge rectangles.
 const dots=spec.panels.length;
 for(let i=0;i<Math.min(8,dots);i++){
   ctx.fillStyle=i===director.current?p.accent:p.line;
   roundBox(ctx,(g.stage.x+g.stage.w-22*width/720)-(dots-i-1)*19*width/720,
     g.stage.y+g.stage.h-24*height/1280, i===director.current?19*s:8*s,5*height/1280,3*s);
   ctx.fill();
 }
 // Presenter in a compact, vertically cropped PiP; independent from content panel.
 if(g.speaker){
   roundedSurface(ctx,g.speaker,p.surface,22*s,p.line);
   const inset=5*s;
   ctx.save();
   roundBox(ctx,g.speaker.x+inset,g.speaker.y+inset,g.speaker.w-2*inset,g.speaker.h-2*inset,17*s);ctx.clip();
   ctx.fillStyle=p.panel;ctx.fillRect(g.speaker.x,g.speaker.y,g.speaker.w,g.speaker.h);
   crop(ctx,src,spec.speaker,g.speaker.x+inset,g.speaker.y+inset,g.speaker.w-inset*2,g.speaker.h-inset*2,sw,sh,true);
   ctx.restore();
 }
 // Subtitle lives in a reserved safety area, never overlaps formulas/diagram.
 const sub=g.subtitles;
 if(subtitle.trim()){
   roundedSurface(ctx,sub,p.caption,18*s);
   const pad=18*s;
   const captionText=String(subtitle).replace(/\s+/g,' ').trim();
   const metrics=fitTypography(ctx,captionText,{
       width:sub.w-pad*2,height:sub.h-pad*2,
       maxFont:32*s,minFont:23*s,maxLines:g.speaker?4:2,weight:700,lineHeight:1.16
   });
   const totalH=metrics.lines.length*metrics.lineHeight;
   const textY=sub.y+(sub.h-totalH)/2;
   ctx.save();ctx.font='700 '+metrics.size+'px system-ui, sans-serif';
   ctx.textBaseline='top';ctx.textAlign='left';ctx.fillStyle='#18233B';
   for(let i=0;i<metrics.lines.length;i++)
     ctx.fillText(metrics.lines[i],sub.x+pad,textY+i*metrics.lineHeight);
   ctx.restore();
 }
 ctx.restore();
}
