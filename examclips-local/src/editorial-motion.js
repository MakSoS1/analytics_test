// Pure editorial layout rules inspired by Remotion agent motion-graphics guidance.
// All calculations are deterministic; both preview and MP4 exporter use them.
export const clamp01 = value => Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
export const easeOutCubic = t => 1 - Math.pow(1 - clamp01(t), 3);
export const smoothstep = t => {const x=clamp01(t);return x*x*(3-2*x)};
export const PALETTES = Object.freeze({
  warm: {background:'#F5F4F0',ink:'#16213B',muted:'#66718A',surface:'#FFFFFF',panel:'#F6F8FB',
    line:'#E4E8EF',accent:'#305FE8',accentSurface:'#EAF0FF',caption:'#FFFFFF'},
  midnight: {background:'#0F1422',ink:'#F6F7FA',muted:'#9DAEC7',surface:'#192234',panel:'#222E43',
    line:'#36445C',accent:'#83AEFF',accentSurface:'#253F66',caption:'#F6F7FA'}
});
export function paletteFor(theme){return PALETTES[theme]||PALETTES.warm}
export function measureWrapped(ctx,text,maxWidth,maxLines=Infinity){
  const words=String(text||'').replace(/\s+/g,' ').trim().split(' ').filter(Boolean);
  const lines=[];let current='';
  const emit=()=>{if(current){lines.push(current);current=''}};
  for(const word of words){
    const together=current?current+' '+word:word;
    if(ctx.measureText(together).width<=maxWidth){current=together;continue}
    emit();
    if(ctx.measureText(word).width<=maxWidth){current=word;continue}
    // Too-long OCR token: split into graphemes instead of drawing outside canvas.
    for(const ch of Array.from(word)){
      if(current&&ctx.measureText(current+ch).width>maxWidth)emit();
      current+=ch;
    }
  }
  emit();
  return {lines:lines.slice(0,maxLines),overflow:lines.length>maxLines};
}
export function fitTypography(ctx,text,{width,height,maxFont=49,minFont=25,lineHeight=1.18,maxLines=10,weight=650}={}){
  const family='system-ui, -apple-system, "Segoe UI", sans-serif';
  for(let size=maxFont;size>=minFont;size--){
    ctx.font=weight+' '+size+'px '+family;
    const wrapped=measureWrapped(ctx,text,width,maxLines);
    if(!wrapped.overflow&&wrapped.lines.length*size*lineHeight<=height){
      return {size,lines:wrapped.lines,lineHeight:size*lineHeight,overflow:false}
    }
  }
  ctx.font=weight+' '+minFont+'px '+family;
  const wrapped=measureWrapped(ctx,text,width,Math.min(maxLines,Math.floor(height/(minFont*lineHeight))));
  return {size:minFont,lines:wrapped.lines,lineHeight:minFont*lineHeight,overflow:wrapped.overflow};
}
export function suitableOcrLines(panel,title=''){
  // Never use low-confidence Tesseract strings or paragraphs too long for a visual card.
  // Technical diagrams and formulas stay as source pixels in the composer.
  if(!Array.isArray(panel?.lines))return [];
  const name=String(title).trim().toLowerCase();
  return panel.lines.map(x=>String(x||'').replace(/\s+/g,' ').trim())
    .filter(x=>x.length>=5&&x.length<=115&&x.toLowerCase()!==name&&!/[{}<>|\\]/.test(x))
    .slice(0,7);
}
export function captionCueAt(chunks,time){
  const cue=(chunks||[]).find(c=>c.start<=time&&c.end>time);
  if(!cue||!cue.text?.trim())return '';
  const text=cue.text.trim().replace(/\s+/g,' ');
  if(text.length<=84)return text;
  const words=text.split(' '),perPage=10,count=Math.ceil(words.length/perPage);
  const ratio=clamp01((time-cue.start)/Math.max(.001,cue.end-cue.start));
  const page=Math.min(count-1,Math.floor(ratio*count));
  return words.slice(page*perPage,(page+1)*perPage).join(' ');
}
export function editorialTimeline(scene,elapsed,{transition=.48}={}){
  const beats=scene?.beats?.length?scene.beats:[{time:0,focus:0}];
  let index=0;
  for(let i=0;i<beats.length;i++){if(elapsed>=beats[i].time)index=i;else break}
  const current=beats[index].focus,previous=beats[Math.max(0,index-1)].focus;
  const changed=index>0&&current!==previous;
  const mix=changed?smoothstep((elapsed-beats[index].time)/transition):1;
  return {current,previous,mix,index,progress:easeOutCubic((elapsed-beats[index].time)/.55)};
}
export function editorialGeometry(width=720,height=1280,{speaker=true}={}){
  const sx=width/720,sy=height/1280;
  const scale=rect=>({x:rect.x*sx,y:rect.y*sy,w:rect.w*sx,h:rect.h*sy});
  return {
    eyebrow:scale({x:42,y:42,w:636,h:32}),
    title:scale({x:42,y:93,w:636,h:108}),
    stage:scale({x:30,y:229,w:660,h:speaker?745:888}),
    speaker:speaker?scale({x:33,y:996,w:255,h:204}):null,
    subtitles:scale(speaker?{x:308,y:1004,w:378,h:170}:{x:38,y:1135,w:644,h:72})
  };
}
