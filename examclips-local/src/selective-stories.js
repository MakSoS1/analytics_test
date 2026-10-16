/**
 * Selective, extractive lecture highlight planner — browser only.
 * This is NOT an LLM understanding of educational merit: decisions are
 * scored as REVIEWABLE CANDIDATES based on transcript evidence.
 * The source remains complete; no pixel/audio is deleted.
 */
import {normalizeChunks,titleFromText} from './segments.js';
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
const STOP=new Set(("this that from with into would could about there these those where which what then have were here " +
 "этого этому когда тогда потом поэтому вообще просто действительно значит который которая потому также будет можно наша ваши ваши вот типа такой такие сами самыми есть при как для они она это однако").split(/\s+/));
const WORD=/[\p{L}\p{N}]{4,}/gu;
function stem(word){
 // Deliberately small suffix normalization, not a morphological guarantee.
 if(/[а-яё]/u.test(word)&&word.length>=7)
   return word.replace(/(?:ования|ование|ениями|ения|ением|ении|ами|ями|ого|ему|ыми|ими|уется|уются|ает|ают|ует|уют|ется|ются|ыми|ой|ые|ия|ие|ия|ов|ев|ам|ям|ах|ях|ом|ем|а|я|ы|и|е|у|ю)$/u,'');
 if(/[a-z]/.test(word)&&word.length>=7)return word.replace(/(?:ing|ation|ions|ers|ed|es|s)$/,'');
 return word;
}
const words=text=>(String(text||'').toLowerCase().match(WORD)||[]).filter(w=>!STOP.has(w)).map(stem).filter(w=>w.length>=4);
const OPEN=/(?:во[- ]первых|главное|почему|как работает|разбер[её]м|например|рассмотрим|причина|важно|imagine|consider|why|how it works|for example|here is|the problem|let's explain)/iu;
const EXPLAIN=/(?:потому что|это значит|это позволяет|например|разница|отличие|следовательно|таким образом|в результате|из-за|поэтому|because|for instance|for example|means that|therefore|as a result|the difference|this allows)/iu;
const LOW_VALUE=/(?:проверка микрофона|перерыв|организационн|слышно меня|подождите минут|давайте подожд[её]м|one moment|technical difficulties|can you hear me|break time|subscribe|like and subscribe)/iu;
const FILLER=/^(?:ну|ээ+|эм+|вот|так|окей|угу|okay|um+|uh+|you know|so)\b/iu;
function cosineLike(a,b){
 const wa=new Set(words(a)),wb=new Set(words(b));if(!wa.size||!wb.size)return 0;
 let common=0;for(const token of wa)if(wb.has(token))common++;
 return common/Math.sqrt(wa.size*wb.size);
}
function captionText(chunks){return chunks.map(x=>x.text).join(' ')}
export function informationScore(text,{seconds=30,pauseAfter=0}={}){
 const tokens=words(text),unique=new Set(tokens);
 const speed=tokens.length/Math.max(seconds,1);
 const density=unique.size/Math.max(1,tokens.length);
 const signal=(OPEN.test(text)?1:0)+(EXPLAIN.test(text)?1.1:0)+
   (/[.!?…]\s*$/u.test(text)?.45:0);
 const penalty=(LOW_VALUE.test(text)?4:0)+(tokens.length<12?1.7:0)+
   (FILLER.test(text)?0.35:0);
 return clamp(.45+density*1.5+signal+Math.min(.85,speed*.24)+
   Math.min(1.2,Math.max(0,pauseAfter)*.25)-penalty,0,7);
}
/**
 * Cut long ASR-observed gaps within a chosen candidate, but retain natural
 * breathing pauses <=1.15 seconds. Does not pretend SRT gives audio-exact VAD.
 */
export function tightSpeechPieces(rows,{gap=1.15,padding=.12}={}){
 if(!rows.length)return [];
 const ranges=[];
 for(const c of rows){
   const a=Math.max(0,c.start-padding),b=c.end+padding;
   if(ranges.length&&a-ranges.at(-1).end<=gap)
     ranges.at(-1).end=Math.max(ranges.at(-1).end,b);
   else ranges.push({start:a,end:b});
 }
 return ranges;
}
export function findLectureCandidates(chunks,duration,{window=42,minSpeechWords=12}={}){
 const rows=normalizeChunks(chunks,duration);
 if(!rows.length)return [];
 const result=[];let group=[];
 const emit=()=>{
  if(!group.length)return;
  const start=group[0].start,end=group.at(-1).end,text=captionText(group);
  const signalWords=words(text).length;
  if(signalWords>=minSpeechWords&&end>start){
   const pause=Math.max(0,(rows.find(r=>r.start>=end+.01)?.start??end)-end);
   const score=informationScore(text,{seconds:end-start,pauseAfter:pause});
   const sourcePieces=tightSpeechPieces(group).map(piece=>({
     start:Math.max(start,piece.start),end:Math.min(end,piece.end)
   }));
   result.push({id:'candidate-'+(result.length+1),start,end,seconds:end-start,
    sourcePieces,
    text,score,keywordSet:[...new Set(words(text))].slice(0,120),
    sourceChunkCount:group.length,
    reason:LOW_VALUE.test(text)?'Организационная речь: пониженный приоритет':
      EXPLAIN.test(text)?'Есть причинно-следственное объяснение или пример':
      OPEN.test(text)?'Есть постановка вопроса или конкретный пример':'Кандидат требует смысловой проверки'});
  }
  group=[];
 };
 for(const row of rows){
   const gap=group.length?row.start-group.at(-1).end:0;
   if(group.length&&(gap>=2.25||row.end-group[0].start>window+Math.max(3,window*.2)))emit();
   group.push(row);
   if(/[.!?…]\s*$/u.test(row.text)&&group.at(-1).end-group[0].start>=window*.65)emit();
 }
 emit();return result;
}
const rangesOverlap=(a,b)=>Math.max(a.start,b.start)<Math.min(a.end,b.end);
export function selectValuableCandidates(candidates,duration,{
 keepFraction=.30,minScore=1.3,maxCandidates=14
}={}){
 if(!(keepFraction>0&&keepFraction<=1))throw Error('keepFraction must be in (0,1]');
 const budget=duration*keepFraction;
 const sorted=[...candidates].filter(c=>c.score>=minScore&&c.seconds>0)
  .sort((a,b)=>b.score-a.score||a.start-b.start);
 const kept=[];let chosen=0;
 for(const c of sorted){
  if(kept.length>=maxCandidates)break;
  if(kept.some(k=>rangesOverlap(k,c)))continue;
  if(chosen+c.seconds>budget+.01)continue;
  kept.push(c);chosen+=c.seconds;
 }
 return kept.sort((a,b)=>a.start-b.start);
}
function orderedDistinct(spans){
 return spans.filter(s=>s.end>s.start).map(s=>({start:s.start,end:s.end}));
}
export function sourceSegments(clip){
 const pieces=Array.isArray(clip?.segments)&&clip.segments.length?
   clip.segments:[{start:clip?.start,end:clip?.end}];
 return orderedDistinct(pieces||[]);
}
export function storyDuration(clip){
 return sourceSegments(clip).reduce((total,s)=>total+(s.end-s.start),0);
}
export function summarizeStoryPlan(clips,duration,candidates=[]){
 const all=(clips||[]).flatMap(c=>sourceSegments(c)).sort((a,b)=>a.start-b.start);
 let covered=0,right=0;
 for(const s of all){const begin=Math.max(s.start,right);covered+=Math.max(0,s.end-begin);right=Math.max(right,s.end)}
 return {sourceSeconds:duration,keptSeconds:+covered.toFixed(2),discardedSeconds:+Math.max(0,duration-covered).toFixed(2),
  keptPercent:duration?Math.round(100*covered/duration):0,
  unusedCandidates:Math.max(0,candidates.length-all.length),stories:clips.length,
  nonContiguousStories:clips.filter(c=>sourceSegments(c).length>1).length};
}
/**
 * Assemble a coherent suggested story from ranked candidate segments.
 * Distant segments are only combined when literal specific terms overlap.
 * Confidence stays low; editor must let a human remove/reorder each segment.
 */
export function planSelectiveStories(chunks,duration,{
 min=35,target=90,max=180,keepFraction=.30,maxStories=8,sceneCuts=[]
}={}){
 if(!Number.isFinite(duration)||duration<=0)return {clips:[],candidates:[],summary:summarizeStoryPlan([],0)};
 if(!(min>=10&&max>=min&&target>=min&&target<=max))throw Error('Invalid story duration');
 const candidates=findLectureCandidates(chunks,duration,{window:Math.min(55,Math.max(20,target*.5))});
 const selected=selectValuableCandidates(candidates,duration,{
  keepFraction,maxCandidates:Math.max(2,maxStories*3)
 });
 const unused=new Set(selected.map(x=>x.id));const clips=[];
 const scoreSorted=[...selected].sort((a,b)=>b.score-a.score||a.start-b.start);
 for(const first of scoreSorted){
  if(!unused.has(first.id)||clips.length>=maxStories)continue;
  unused.delete(first.id);
  const group=[first];let total=first.seconds;
  const related=scoreSorted.filter(c=>unused.has(c.id)&&c.id!==first.id)
   .map(c=>({candidate:c,similarity:cosineLike(first.text,c.text)}))
   .filter(x=>x.similarity>=.135).sort((a,b)=>b.similarity-a.similarity||a.candidate.start-b.candidate.start);
  for(const {candidate,similarity} of related){
   if(group.length>=3||total>=target*.9)break;
   if(total+candidate.seconds>max)continue;
   if(candidate.score<1.35)continue;
   group.push(candidate);unused.delete(candidate.id);total+=candidate.seconds;
  }
  // Short but useful stand-alone material may still be presented for human review.
  const spans=group.sort((a,b)=>a.start-b.start);
  const firstText=spans.map(x=>x.text).join(' ');
  const start=Math.min(...spans.map(x=>x.start)),end=Math.max(...spans.map(x=>x.end));
  const diversity=group.length>1;
  clips.push({id:'story-'+(clips.length+1),start,end,
   segments:spans.flatMap(x=>x.sourcePieces||[{start:x.start,end:x.end}]),
   title:titleFromText([...spans].sort((a,b)=>b.score-a.score)[0].text),
   layout:'hybrid',focusX:50,confidence:'low',status:'needs-review',method:'selective-extractive',
   storyScore:+(group.reduce((n,c)=>n+c.score,0)/group.length).toFixed(2),
   reviewReasons:[
     'Фрагменты отобраны по признакам содержательности; подтвердите смысл и отсутствие вырванных из контекста утверждений',
     ...(diversity?['Несмежные участки объединены по совпадению терминов, а не по доказанной смысловой связи']:[]),
     ...(total<min?['Короткая микротема: можно расширить вручную']:[])
   ],
   evidence:spans.map(x=>({time:x.start,reason:x.reason,score:+x.score.toFixed(2)})),
   outputSeconds:+spans.flatMap(x=>x.sourcePieces||[{start:x.start,end:x.end}]).reduce((n,p)=>n+p.end-p.start,0).toFixed(2)});
 }
 clips.sort((a,b)=>b.storyScore-a.storyScore||a.start-b.start);
 const summary=summarizeStoryPlan(clips,duration,candidates);
 return {clips,candidates,summary,unselected:candidates.filter(c=>!selected.some(s=>s.id===c.id))};
}
export function splitTranscriptForStory(chunks,clip){
 const parts=sourceSegments(clip);
 return (chunks||[]).filter(c=>parts.some(p=>c.end>p.start&&c.start<p.end));
}
