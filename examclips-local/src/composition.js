export const WIDTH=720,HEIGHT=1280;
function lineWrap(ctx,text,maxWidth){
  const words=text.trim().split(/\s+/),lines=[],current={v:''};
  for(const w of words){const next=(current.v?current.v+' ':'')+w;
    if(ctx.measureText(next).width>maxWidth&&current.v){lines.push(current.v);current.v=w}else current.v=next}
  if(current.v)lines.push(current.v);return lines.slice(0,4);
}
export function paintFrame(canvas,source,width,height,layout,focusX,subtitle=''){
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
