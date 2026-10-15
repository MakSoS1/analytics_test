/** Deterministic, dependency-free segmentation. No claims of semantic AI scoring. */
export function validRange(start,end,duration){
  return Number.isFinite(start)&&Number.isFinite(end)&&Number.isFinite(duration)&&start>=0&&end>start&&end<=duration+.001;
}
export function normalizeChunks(chunks,duration){
  const safe=chunks.filter(c=>c&&typeof c.text==='string'&&c.text.trim()&&Number.isFinite(c.start)&&Number.isFinite(c.end))
    .map(c=>({text:c.text.trim(),start:Math.max(0,c.start),end:Math.min(duration,c.end)}))
    .filter(c=>c.end>c.start).sort((a,b)=>a.start-b.start);
  return safe;
}
export function titleFromText(text){
  const clean=text.replace(/[^\p{L}\p{N}\s-]/gu,'').trim().replace(/\s+/g,' ');
  return (clean.split(' ').slice(0,8).join(' ')||'Фрагмент лекции').slice(0,90);
}
export function buildClips(chunks,duration,{min=30,target=90,max=180}={}){
  if(!Number.isFinite(duration)||duration<=0) return [];
  if(!(min>0&&max>=min&&target>=min&&target<=max)) throw Error('Invalid segmentation limits');
  const clean=normalizeChunks(chunks,duration),clips=[];
  if(!clean.length) return [{id:'clip-1',start:0,end:Math.min(duration,target),title:'Фрагмент 1',layout:'fit',focusX:50}];
  let i=0;
  while(i<clean.length&&clips.length<200){
    let j=i,begin=clean[i].start;
    while(j+1<clean.length&&clean[j].end-begin<min)j++;
    let best=j;
    let scoreBest=Infinity;
    for(let k=j;k<clean.length;k++){
      const length=clean[k].end-begin;
      if(length>max&&k>j)break;
      const pause=k+1<clean.length?Math.max(0,clean[k+1].start-clean[k].end):2;
      const isSentence=/[.!?…]$/.test(clean[k].text);
      const score=Math.abs(length-target)-Math.min(3,pause)*7-(isSentence?9:0);
      if(length>=min&&length<=max&&score<scoreBest){best=k;scoreBest=score}
      if(length>max)break;
    }
    if(clean[best].end-begin>max&&best>i)best--;
    const end=Math.min(duration,Math.max(begin+Math.min(min,duration-begin),clean[best].end));
    if(end<=begin)break;
    clips.push({id:'clip-'+(clips.length+1),start:begin,end,title:titleFromText(clean.slice(i,best+1).map(x=>x.text).join(' ')),layout:'fit',focusX:50});
    i=best+1;
  }
  if(!clips.length) return [];
  // Avoid a tiny dangling fragment by expanding the preceding clip within the maximum.
  const last=clips.at(-1),prior=clips.at(-2);
  if(prior&&last.end-last.start<min&&last.end-prior.start<=max){prior.end=last.end;clips.pop()}
  return clips;
}
export function timecode(seconds,comma=false){
  const ms=Math.max(0,Math.round(seconds*1000)),h=Math.floor(ms/3600000),m=Math.floor(ms/60000)%60,s=Math.floor(ms/1000)%60,r=ms%1000;
  return [h,m,s].map(x=>String(x).padStart(2,'0')).join(':')+(comma?',':'.')+String(r).padStart(3,'0');
}
export function toSrt(chunks){
  return chunks.map((c,i)=>`${i+1}\n${timecode(c.start,true)} --> ${timecode(c.end,true)}\n${c.text.trim()}\n`).join('\n');
}
export function parseSrt(text,duration=Infinity){
  const blocks=text.replace(/\r/g,'').trim().split(/\n\s*\n/),out=[];
  const parse=t=>{const match=t.match(/^(\d{2}):(\d{2}):(\d{2})[,.](\d{1,3})$/);return match?+match[1]*3600 + +match[2]*60 + +match[3]+ +(match[4].padEnd(3,'0'))/1000:NaN};
  for(const block of blocks){
    const lines=block.split('\n');const ti=lines.findIndex(l=>l.includes(' --> '));
    if(ti<0)continue;const [a,b]=lines[ti].split(' --> ').map(t=>parse(t.trim()));
    if(validRange(a,b,duration)){const content=lines.slice(ti+1).join(' ').replace(/<[^>]*>/g,'').trim();if(content)out.push({start:a,end:b,text:content})}
  }
  return normalizeChunks(out,duration);
}
export function textAt(chunks,time){return chunks.find(c=>c.start<=time&&c.end>time)?.text||''}
