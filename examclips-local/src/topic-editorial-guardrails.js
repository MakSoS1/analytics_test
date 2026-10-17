/**
 * Enforce basic editorial invariants AFTER fine-grained topic detection:
 *   - each suggested lesson must have enough contextual speech,
 *   - source timestamps belong to only one final clip,
 *   - near-identical ASR/repeated lectures do not create repeat shorts,
 *   - a standalone outline/transition isn't masquerading as a lesson.
 *
 * No quota or maximum clip length. Decisions are deterministic and auditable.
 */
const WORD=/[\p{L}\p{N}]{3,}/gu;
const STOP=new Set('the and from with this that what then they them these there into your for are was were will shall can may who how when because therefore also have has had our you for example например поэтому значит который которая которые также будет можно для как при этой этого этом теме topic docker containers container'.split(/\s+/));
export const tokens=text=>(String(text||'').toLowerCase().match(WORD)||[]).filter(w=>!STOP.has(w));
export const rowSeconds=rows=>(rows||[]).reduce((n,r)=>n+Math.max(0,r.end-r.start),0);
const setText=rows=>tokens(rows.map(r=>r.text).join(' '));
const unique=(words)=>new Set(words);
function jaccard(a,b){
 const x=unique(a),y=unique(b);if(!x.size||!y.size)return 0;
 let shared=0;for(const t of x)if(y.has(t))shared++;
 return shared/(x.size+y.size-shared);
}
function coverage(a,b){
 const x=unique(a),y=unique(b);if(!x.size)return 0;
 let hit=0;for(const t of x)if(y.has(t))hit++;
 return hit/x.size;
}
function charFingerprint(value){return String(value||'').toLowerCase().replace(/[^\p{L}\p{N}]+/gu,' ').trim().replace(/\s+/gu,' ')}
/** Removes *actual* duplicates. Reusing Docker terms does not imply repeated teaching. */
export function dedupeTranscriptRows(rows, {maxRepeatGap=2.5}={}){
 const sorted=[...rows].sort((a,b)=>a.start-b.start||a.end-b.end);
 const clean=[],removed=[];
 for(const row of sorted){
   const fp=charFingerprint(row.text);
   const recent=clean.slice(-30).find(x=>row.start-x.end<maxRepeatGap&&
     (charFingerprint(x.text)===fp||
       (fp.length>=55&&x.text.length>=55&&
        jaccard(tokens(row.text),tokens(x.text))>.94&&
        coverage(tokens(row.text),tokens(x.text))>.96)));
   if(recent){removed.push({...row,reason:'Повтор той же расшифрованной реплики'});continue}
   clean.push(row);
 }
 return {rows:clean,removed};
}
function groupInfo(g){
 const rows=g.rows;
 return {seconds:rowSeconds(rows),words:rows.reduce((n,r)=>n+String(r.text||'').split(/\s+/).filter(Boolean).length,0),
   begin:rows[0].start,end:rows.at(-1).end};
}
function sameChapter(a,b){
 return a.chapter?.key&&b.chapter?.key&&a.chapter.key===b.chapter.key;
}
function commonEvidence(a,b){
 const aWords=setText(a.rows),bWords=setText(b.rows);
 return coverage(aWords,bWords);
}
function compatible(a,b){
 if(!a||!b)return false;
 const x=groupInfo(a),y=groupInfo(b);
 if(y.begin-x.end>35)return false; // don't jump across lengthy unrelated material
 const shared=commonEvidence(a,b),backwards=commonEvidence(b,a);
 // The same slide may contain several distinct lessons. Never combine two
 // different concepts merely because their chapter heading matches.
 if(sameChapter(a,b))return shared>.24||backwards>.24||
   (groupInfo(b).seconds<12&&shared>.13);
 // Across distinct slide headings, demand strong explanatory continuity.
 return shared>.62&&backwards>.48;
}
function combine(a,b){
 return {rows:[...a.rows,...b.rows].sort((x,y)=>x.start-y.start),
   chapter:a.chapter||b.chapter,editorialNotes:[...(a.editorialNotes||[]),...(b.editorialNotes||[]),'Объединено: слишком короткая неполная мысль']};
}
function brief(g){
 const v=groupInfo(g);
 // Don't punish slowly spoken / sparse synthetic transcripts which still
 // span a coherent explanation. A short candidate is a TIME/context issue.
 return v.seconds<28||(v.seconds<40&&v.words<15)||
   (g.rows.length<2&&v.seconds<18);
}
function viable(g){
 const x=groupInfo(g);
 const sentence=g.rows.map(r=>r.text).join(' ');
 const explanatory=/(?:потому|поэтому|например|позволя|означает|представляет|в\s+отличие|for example|because|means|allow|is\s+a|are\s+a)/iu.test(sentence);
 return x.seconds>=12&&x.words>=14&&
   (g.rows.length>=2||x.seconds>=26||(x.seconds>=17&&explanatory));
}
/**
 * Merge only coherent adjacent micro-candidates; discard isolated
 * sub-10-second filler rather than attaching a nonsense sentence to
 * an unrelated lesson. Keep lone 20s complete explanations for review.
 */
export function consolidateMicrotopics(proposals){
 const working=proposals.filter(g=>g?.rows?.length).map(g=>({...g,rows:[...g.rows]}));
 const omitted=[];
 for(let i=0;i<working.length;i++){
   const g=working[i];if(!brief(g))continue;
   const before=working[i-1],after=working[i+1];
   const prevCompatible=compatible(before,g);
   const nextCompatible=compatible(g,after);
   if((prevCompatible||nextCompatible)&&groupInfo(g).seconds<28){
     if(prevCompatible&&(!nextCompatible||commonEvidence(g,before)>=commonEvidence(g,after))){
       working[i-1]=combine(before,g);working.splice(i,1);
     }else{
       working[i+1]=combine(g,after);working.splice(i,1);
     }
     i=Math.max(-1,i-2);
   }else if(!viable(g)){
     omitted.push(...g.rows.map(r=>({...r,reason:'Отдельная реплика не образует понятную микротему'})));
     working.splice(i,1);i--;
   }else{
     // 12-30 seconds is acceptable only as a flagged single self-contained
     // explanation when joining is unsafe (different unrelated chapter).
     g.editorialNotes=[...(g.editorialNotes||[]),'Короткая тема: проверьте, что она понятна самостоятельно'];
   }
 }
 // Near-verbatim repeated explanations are not additional chapters in a course.
 const final=[];
 for(const g of working){
   const words=setText(g.rows);
   const match=final.find(prev=>prev.chapter?.key===g.chapter?.key&&
     words.length>=8&&setText(prev.rows).length>=8&&
     coverage(words,setText(prev.rows))>.93&&
     coverage(setText(prev.rows),words)>.84&&
     jaccard(words,setText(prev.rows))>.87);
   if(match)omitted.push(...g.rows.map(r=>({...r,reason:'Повтор уже раскрытой микротемы без новых фактов'})));
   else final.push(g);
 }
 return {groups:final,omitted,mergedCount:proposals.length-working.length};
}
/**
 * Guarantee no source-second is rendered twice across successive clips.
 * Not a wall-clock cap; overlapping ASR and ±120 ms pad are the issue.
 */
export function assignExclusiveSource(clips){
 let claimedUntil=0;
 const output=[];
 for(const clip of clips){
   const parts=(clip.segments||[{start:clip.start,end:clip.end}])
      .slice().sort((a,b)=>a.start-b.start);
   const spans=[];
   for(const part of parts){
     const start=Math.max(part.start,claimedUntil);
     if(part.end-start<.08)continue;
     if(spans.length&&start-spans.at(-1).end<=.06)
       spans.at(-1).end=Math.max(spans.at(-1).end,part.end);
     else spans.push({start,end:part.end});
     claimedUntil=Math.max(claimedUntil,part.end);
   }
   if(!spans.length)continue;
   output.push({...clip,start:spans[0].start,end:spans.at(-1).end,segments:spans,
     outputSeconds:+spans.reduce((n,x)=>n+x.end-x.start,0).toFixed(2)});
 }
 return output;
}
