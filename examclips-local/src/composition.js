import {makeStoryboard,sourceRect,sceneAt,assertScene} from './scene-model.js';
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

function drawSourceRegion(ctx,src,region,dx,dy,dw,dh,sw,sh){
  const s=sourceRect(region,sw,sh),scale=Math.min(dw/s.w,dh/s.h);
  const rw=s.w*scale,rh=s.h*scale,rx=dx+(dw-rw)/2,ry=dy+(dh-rh)/2;
  if(typeof src.draw==='function')src.draw(ctx,s.x,s.y,s.w,s.h,rx,ry,rw,rh);
  else ctx.drawImage(src,s.x,s.y,s.w,s.h,rx,ry,rw,rh);
}
function roundRect(ctx,x,y,w,h,r){ctx.beginPath();ctx.roundRect(x,y,w,h,r);ctx.closePath()}
export function paintHybrid(canvas,src,sw,sh,subtitle='',scene=null,elapsed=0){
  const c=canvas.getContext('2d'),w=canvas.width,h=canvas.height;
  const spec=assertScene(scene)?scene:makeStoryboard({width:sw,height:sh,duration:60});
  const active=sceneAt(spec,Math.max(0,elapsed)).focus;
  const panel=spec.panels[active]||spec.panels[0];
  c.fillStyle='#f7f9fd';c.fillRect(0,0,w,h);
  c.fillStyle='#e9edf5';c.fillRect(0,0,w,10);
  // Preserve actual slide header as pixels, rather than trusting potentially inaccurate OCR.
  c.save();roundRect(c,26,28,w-52,130,20);c.clip();
  c.fillStyle='#fff';c.fillRect(26,28,w-52,130);
  drawSourceRegion(c,src,{x:0,y:0,w:.79,h:.17},36,41,w-72,96,sw,sh);
  c.restore();
  c.save();roundRect(c,24,178,w-48,762,26);c.clip();
  c.fillStyle='#fff';c.fillRect(24,178,w-48,762);
  drawSourceRegion(c,src,panel.rect,37,200,w-74,710,sw,sh);c.restore();
  c.strokeStyle='#e5eaf3';c.lineWidth=2;roundRect(c,24,178,w-48,762,26);c.stroke();
  if(spec.panels.length>1){
    const secondary=spec.panels[(active+1)%spec.panels.length];
    c.save();roundRect(c,w-206,794,175,122,15);c.clip();
    c.fillStyle='#e7eff8';c.fillRect(w-206,794,175,122);
    drawSourceRegion(c,src,secondary.rect,w-199,799,161,112,sw,sh);c.restore();
  }
  c.fillStyle='#40526e';c.font='600 19px system-ui';
  c.fillText('EXAMCLIPS  ·  '+(active+1)+' / '+spec.panels.length,34,975);
  // Speaker is a separate animated video layer, independent of the active slide region.
  c.save();roundRect(c,40,988,w-80,177,22);c.clip();
  c.fillStyle='#e6edf5';c.fillRect(40,988,w-80,177);
  drawSourceRegion(c,src,spec.speaker,48,992,w-96,168,sw,sh);c.restore();
  if(subtitle.trim()){
    c.font='bold 28px system-ui';c.textAlign='center';
    const words=subtitle.split(/\s+/),lines=[];let current='';
    for(const word of words){
      const next=(current?current+' ':'')+word;
      if(c.measureText(next).width>w-64&&current){lines.push(current);current=word}else current=next;
    }if(current)lines.push(current);
    lines.slice(0,2).forEach((line,i)=>{
      c.strokeStyle='#fff';c.lineWidth=7;c.strokeText(line,w/2,1190+i*34);
      c.fillStyle='#101b30';c.fillText(line,w/2,1190+i*34);
    });
  }
}
