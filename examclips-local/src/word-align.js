/** Group local Whisper word-timestamp events into short, correctly timed clauses.
 * This keeps semantic segmenter input sane while providing precise word arrays for captions.
 */
export function packWordEvents(items,base,end){
 const safe=(items||[]).map(c=>{
   const t=c?.timestamp;
   if(!Array.isArray(t)||!Number.isFinite(t[0])||!Number.isFinite(t[1])||!String(c.text||'').trim())return null;
   const start=Math.max(base,Math.min(end,base+t[0]));
   const finish=Math.max(start,Math.min(end,base+t[1]));
   return finish>start?{start,end:finish,text:String(c.text).trim()}:null;
 }).filter(Boolean).sort((a,b)=>a.start-b.start);
 if(!safe.length)return [];
 const out=[];let group=[];
 const flush=()=>{
   if(!group.length)return;
   out.push({start:group[0].start,end:group.at(-1).end,
    text:group.map(x=>x.text).join(' '),
    words:group.map(x=>({...x}))});
   group=[];
 };
 for(const w of safe){
   if(group.length&&((w.start-group.at(-1).end)>.8||(w.end-group[0].start)>8.5||group.length>=15))flush();
   group.push(w);
   if(/[.!?…]$/u.test(w.text)&&group.length>=3)flush();
 }
 flush();return out;
}
