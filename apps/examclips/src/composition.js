import {makeStoryboard,sourceRect,assertScene} from './scene-model.js';
import {editorialTimeline,editorialGeometry,fitTypography,suitableOcrLines,paletteFor,titleCardOpacity} from './editorial-motion.js';
export const WIDTH=720,HEIGHT=1280;
function lineWrap(ctx,text,maxWidth){
  const words=text.trim().split(/\s+/),lines=[],current={v:''};
  for(const w of words){const next=(current.v?current.v+' ':'')+w;
    if(ctx.measureText(next).width>maxWidth&&current.v){lines.push(current.v);current.v=w}else current.v=next}
  if(current.v)lines.push(current.v);return lines.slice(0,4);
}
export function paintFrame(canvas,source,width,height,layout,focusX,subtitle='',scene=null,elapsed=0,lessonElapsed=elapsed){
  if(layout==='hybrid')return paintHybrid(canvas,source,width,height,subtitle,scene,elapsed,lessonElapsed);
  subtitle=typeof subtitle==='string'?subtitle:(subtitle?.plain||'');
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
 ctx.beginPath();ctx.rect(stage.x,stage.y,stage.w,stage.h);ctx.clip();
 const sourceRectArea=stage;
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
   // Subdue white slide backgrounds without changing the source's content.
   ctx.filter='brightness(0.88)';
   crop(ctx,src,panel.rect,sourceRectArea.x,sourceRectArea.y,sourceRectArea.w,sourceRectArea.h,sw,sh);
   ctx.filter='none';
 }
 ctx.restore();
}
export function paintHybrid(canvas,src,sw,sh,subtitle='',scene=null,elapsed=0,lessonElapsed=elapsed){
 const ctx=canvas.getContext('2d'),actualWidth=canvas.width,actualHeight=canvas.height;
 // Compose in logical 720x1280 coordinates; vector text draws sharply at any export resolution.
 const width=720,height=1280;
 ctx.save();
 ctx.setTransform(actualWidth/width,0,0,actualHeight/height,0,0);
 const chapter=scene?.chapters?.findLast(item=>item.start<=elapsed)||null;
 const spec=assertScene(chapter?.scene)?chapter.scene:
   (assertScene(scene)?scene:makeStoryboard({width:sw,height:sh,duration:90}));
 const t=Math.max(0,elapsed-(chapter?.start||0));
 const director=editorialTimeline(spec,t);
 const theme=scene?.theme||spec.theme||'midnight';
 const p=paletteFor(theme),g=editorialGeometry(width,height,{speaker:!spec.hideSpeaker});
 const s=width/720;
 ctx.clearRect(0,0,width,height);
 ctx.fillStyle=p.background;ctx.fillRect(0,0,width,height);
 const currentPanel=spec.panels[director.current]||spec.panels[0];
 // One legible source region per moment. No companion thumbnail or frame chrome.
 if(director.mix<1){
   renderEditorialPanel(ctx,src,sw,sh,spec.panels[director.previous]||currentPanel,g.stage,p,{opacity:1-director.mix});
 }
 renderEditorialPanel(ctx,src,sw,sh,currentPanel,g.stage,p,{opacity:director.mix,reveal:1});
 if(g.speaker)crop(ctx,src,spec.speaker,g.speaker.x,g.speaker.y,g.speaker.w,g.speaker.h,sw,sh,true);
 // Reels-style transparent karaoke captions: no box, no permanently reserved space.
 // Draw only words already spoken, 2-4 at a time, with a subtle pop/highlight.
 const cap=subtitle&&typeof subtitle==='object'?subtitle:null;
 const tokens=cap?.words||[];
 if(tokens.length){
     const fontSize=39*s,baseline=g.subtitles.y+69*s;
   ctx.save();
   ctx.textAlign='left';ctx.textBaseline='alphabetic';
   ctx.font='850 '+fontSize+'px system-ui, sans-serif';
   const desiredWidths=tokens.map(w=>ctx.measureText(w.text).width);
   const unscaledWidth=desiredWidths.reduce((a,b)=>a+b,0)+(tokens.length-1)*12*s;
   const adapt=Math.min(1,(g.subtitles.w-4*s)/Math.max(1,unscaledWidth));
   ctx.translate(g.subtitles.x+(g.subtitles.w-unscaledWidth*adapt)/2,0);
   ctx.scale(adapt,adapt);
   let xx=0;
   for(const word of tokens){
     if(word.visible){
       const isActive=word.active;
       const opacity=isActive?1:.94;
       ctx.save();ctx.globalAlpha=opacity;
       const pop=isActive?1.018+.023*(1-Math.min(1,cap.progress*4)):1;
       const middle=xx+ctx.measureText(word.text).width/2;
       ctx.translate(middle,baseline/adapt);
       ctx.scale(pop,pop);
       ctx.font='850 '+fontSize+'px system-ui, sans-serif';
       ctx.lineJoin='round';ctx.lineWidth=4*s;ctx.strokeStyle='#071021';
       ctx.shadowColor='#07102199';ctx.shadowBlur=3*s;
       ctx.strokeText(word.text,-(desiredWidths[tokens.indexOf(word)]/2),0);
       ctx.shadowBlur=0;
       ctx.fillStyle=isActive?'#73B3FF':'#FFFFFF';
       ctx.fillText(word.text,-(desiredWidths[tokens.indexOf(word)]/2),0);
       ctx.restore();
     }
     xx+=desiredWidths[tokens.indexOf(word)]+12*s;
   }
   ctx.restore();
 }else if(typeof subtitle==='string'&&subtitle.trim()){
   // Compatibility with old callers; still no subtitle rectangle.
   const text=subtitle.replace(/\s+/g,' ').slice(0,70);
   ctx.save();ctx.font='850 39px system-ui, sans-serif';ctx.textAlign='center';
   ctx.lineJoin='round';ctx.lineWidth=9;ctx.strokeStyle='#081322';
   ctx.strokeText(text,width/2,g.subtitles.y+63);
   ctx.fillStyle='#fff';ctx.fillText(text,width/2,g.subtitles.y+63);ctx.restore();
 }
 const title=(scene?.title||spec.title||'').replace(/\s+/gu,' ').trim();
 const intro=title?titleCardOpacity(lessonElapsed):0;
 if(intro>0){
  ctx.save();ctx.globalAlpha=intro;ctx.fillStyle=p.background;ctx.fillRect(0,0,width,height);
  const fit=fitTypography(ctx,title,{width:g.title.w,height:g.title.h,maxFont:58,minFont:29,maxLines:6,lineHeight:1.15,weight:700});
  ctx.font='700 '+fit.size+'px system-ui, sans-serif';ctx.textAlign='center';ctx.textBaseline='top';ctx.fillStyle=p.ink;
  const top=(height-fit.lines.length*fit.lineHeight)/2;
  fit.lines.forEach((line,i)=>ctx.fillText(line,width/2,top+i*fit.lineHeight));ctx.restore();
 }
 ctx.restore();
}
