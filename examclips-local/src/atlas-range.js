/**
 * Source-time operations for Atlas. Discovery only reads saved transcript;
 * accepting a proposal and changing an existing edit are separate UI actions.
 */
import {planCompleteTopics} from './complete-topics.js';
import {buildVerifiedLessonScreenplays} from './lesson-screenplay.js';

const validDuration=duration=>Number.isFinite(duration)&&duration>0;
const validRange=(start,end,duration)=>validDuration(duration)&&
 Number.isFinite(start)&&Number.isFinite(end)&&start>=0&&end>start&&end<=duration;
const overlaps=(a,b)=>a.start<b.end&&a.end>b.start;

// Copy ranges before sorting/merging: a saved EDL may intentionally have a
// different playback order and must never be changed by a coverage calculation.
function clipSpans(clip,duration){
 if(!clip||clip.id==='draft-1')return [];
 const parts=Array.isArray(clip.segments)&&clip.segments.length?
  clip.segments:[{start:clip.start,end:clip.end}];
 return parts.filter(p=>Number.isFinite(p?.start)&&Number.isFinite(p?.end))
  .map(p=>({start:Math.max(0,p.start),end:Math.min(duration,p.end)}))
  .filter(p=>p.end>p.start);
}

function unionSpans(spans){
 const union=[];
 for(const span of [...spans].sort((a,b)=>a.start-b.start||a.end-b.end)){
  const prior=union.at(-1);
  if(prior&&span.start<=prior.end)prior.end=Math.max(prior.end,span.end);
  else union.push({...span});
 }
 return union;
}

function gapsBetween(included,start,end){
 const gaps=[];let cursor=start;
 for(const span of included){
  if(span.end<=cursor)continue;
  if(span.start>=end)break;
  if(span.start>cursor)gaps.push({start:cursor,end:Math.min(span.start,end)});
  cursor=Math.max(cursor,Math.min(span.end,end));
 }
 if(cursor<end)gaps.push({start:cursor,end});
 return gaps;
}

/** Real source-time coverage; this percentage does not measure topic quality. */
export function coverageSpans(clips,duration){
 if(!validDuration(duration))return {included:[],gaps:[],includedSeconds:0,percent:0};
 const included=unionSpans((Array.isArray(clips)?clips:[])
  .filter(c=>c&&!c.candidate).flatMap(c=>clipSpans(c,duration)));
 const includedSeconds=included.reduce((sum,p)=>sum+p.end-p.start,0);
 return {included,gaps:gapsBetween(included,0,duration),includedSeconds,
  percent:Math.min(100,100*includedSeconds/duration)};
}

/**
 * Return fresh review candidates without changing chunks, clips or approvals.
 * Whole source cues only: selecting half a sentence never fabricates timing
 * for its complete quote. Existing candidates also reserve their source spans.
 */
export function findRangeTopics(chunks,duration,{
 start,end,clips=[],chapters=[],sceneCuts=[]
}={}){
 if(!validRange(start,end,duration)||!Array.isArray(chunks))return [];
 const existing=Array.isArray(clips)?clips:[];
 let occupied=unionSpans(existing.flatMap(c=>clipSpans(c,duration)));
 const available=gapsBetween(occupied,start,end);
 const rows=chunks.filter(c=>c&&typeof c.text==='string'&&c.text.trim()&&
   Number.isFinite(c.start)&&Number.isFinite(c.end)&&c.end>c.start&&
   c.start>=start&&c.end<=end)
  .map(c=>({start:c.start,end:c.end,text:c.text}))
  .sort((a,b)=>a.start-b.start||a.end-b.end);
 const outline=Array.isArray(chapters)?chapters.filter(c=>c&&typeof c==='object'):[];
 const cuts=Array.isArray(sceneCuts)?sceneCuts.filter(Number.isFinite):[];
 const usedIds=new Set(existing.map(c=>c?.id));
 const candidates=[];
 for(const free of available){
  // Plan separately around occupied seconds. Even the planner's small audio
  // padding cannot bridge a gap that belongs to an existing manual edit.
  const freeRows=rows.filter(c=>c.start>=free.start&&c.end<=free.end);
  if(freeRows.length<2)continue;
  const plan=planCompleteTopics(freeRows,duration,{chapters:outline,sceneCuts:cuts});
  for(const proposal of plan.clips){
   const proposedSpans=clipSpans(proposal,duration);
   const evidenceRows=freeRows.filter(c=>proposedSpans.some(p=>c.start>=p.start&&c.end<=p.end));
   const [verified]=buildVerifiedLessonScreenplays([proposal],evidenceRows);
   if(!verified.screenplay?.quality?.readyForReview)continue;
   const segments=clipSpans(verified,duration);
   if(!segments.length||segments.some(p=>p.start<free.start||p.end>free.end||
     occupied.some(taken=>overlaps(p,taken))))continue;
   const outputSeconds=segments.reduce((sum,p)=>sum+p.end-p.start,0);
   if(outputSeconds<10)continue;
   const baseId='range-topic-'+segments.map(p=>p.start+'_'+p.end).join('__');
   let id=baseId,suffix=2;
   while(usedIds.has(id))id=baseId+'-'+suffix++;
   usedIds.add(id);
   candidates.push({...verified,id,segments,outputSeconds,
    candidate:true,status:'needs-review'});
   occupied=unionSpans([...occupied,...segments]);
  }
 }
 return candidates;
}

function uuid(){
 if(globalThis.crypto?.randomUUID)return globalThis.crypto.randomUUID();
 // IDs are not security tokens; the fallback keeps local drafts usable in a
 // browser without randomUUID while retaining the UUID version/variant shape.
 return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{
  const n=Math.floor(Math.random()*16);
  return (c==='x'?n:(n&3)|8).toString(16);
 });
}

/** Explicit source selection creates a draft, never a claimed complete lesson. */
export function manualRangeClip(start,end,duration){
 if(!validRange(start,end,duration))
  throw new RangeError('Выберите корректный диапазон внутри исходной лекции');
 if(end-start<10)throw new RangeError('Ручной фрагмент должен длиться не меньше 10 секунд');
 return {
  id:uuid(),start,end,segments:[{start,end}],outputSeconds:end-start,
  title:'Ручной фрагмент',thumbnailTime:start+Math.min(6,(end-start)*.2),
  candidate:true,status:'needs-review',editorialStatus:'needs-more-context',
  method:'manual-range',kind:'explanation',confidence:'low',layout:'hybrid',focusX:50,
  reviewReasons:['Границы выбраны вручную: проверьте связность, начало и завершённость объяснения']
 };
}
