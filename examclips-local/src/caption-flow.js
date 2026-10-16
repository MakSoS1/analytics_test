/**
 * Reels-style karaoke captions. Render 2-5 words on top of the actual visual,
 * progressively revealing them; no permanent subtitle panel.
 * When ASR/SRT provides only sentence timestamps, individual word times are ESTIMATES.
 */
export const captionWords=text=>String(text||'').trim().split(/\s+/u).filter(Boolean);
const clamp=(x,a,b)=>Math.max(a,Math.min(b,x));
function inferWordTimes(cue) {
 const tokens=captionWords(cue.text);
 if(!tokens.length)return [];
 if(Array.isArray(cue.words)&&cue.words.length===tokens.length&&cue.words.every(w=>
  w&&Number.isFinite(w.start)&&Number.isFinite(w.end)&&w.end>w.start)){
   return cue.words.map((w,i)=>({text:tokens[i],start:w.start,end:w.end,precise:true}));
 }
 const length=cue.end-cue.start;
 const weights=tokens.map(w=>.7+Math.min(12,w.replace(/[^\p{L}\p{N}]/gu,'').length)*.17);
 const total=weights.reduce((s,w)=>s+w,0);
 let cumulative=0;
 return tokens.map((token,i)=>{
   const start=cue.start+length*cumulative/total;cumulative+=weights[i];
   return {text:token,start,end:i===tokens.length-1?cue.end:cue.start+length*cumulative/total,precise:false};
 });
}
export function captionSequenceAt(chunks,time,{groupSize=4}={}){
 const cue=(chunks||[]).find(c=>c&&Number.isFinite(c.start)&&Number.isFinite(c.end)&&c.end>c.start&&time>=c.start&&time<c.end&&c.text?.trim());
 if(!cue)return null;
 const wordTimes=inferWordTimes(cue);
 if(!wordTimes.length)return null;
 const active=Math.min(wordTimes.length-1,Math.max(0,wordTimes.findIndex(w=>time<w.end)));
 const max=clamp(Math.floor(groupSize),2,5);
 const start=Math.floor(active/max)*max;
 const current=wordTimes.slice(start,start+max);
 const shown=current.map((w,i)=>({...w,visible:start+i<=active,active:start+i===active}));
 return {
   words:shown,plain:shown.filter(w=>w.visible).map(w=>w.text).join(' '),
   activeIndex:active-start,wordCount:wordTimes.length,
   precise:wordTimes.every(w=>w.precise),
   progress:clamp((time-wordTimes[active].start)/Math.max(.001,wordTimes[active].end-wordTimes[active].start),0,1),
   start:current[0].start,end:current.at(-1).end
 };
}
