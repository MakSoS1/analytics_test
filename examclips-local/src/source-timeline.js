/** Source edit timeline: sparse keep regions and repeat segments of one story. */
import {sourceSegments} from './selective-stories.js';
export function timelinePieces(clips,duration){
 if(!Number.isFinite(duration)||duration<=0)return [];
 const intervals=(clips||[]).filter(c=>c&&c.id!=='draft-1')
  .flatMap(c=>sourceSegments(c).map((segment,segmentIndex)=>({
    id:c.id,segmentIndex,title:c.title||'Фрагмент',start:Math.max(0,Math.min(duration,segment.start)),
    end:Math.max(0,Math.min(duration,segment.end)),status:c.status||'needs-review'
  }))).filter(s=>s.end>s.start).sort((a,b)=>a.start-b.start||a.end-b.end);
 const spans=[];let cursor=0;
 for(const piece of intervals){
   if(piece.start>cursor+1e-4)spans.push({kind:'skipped',start:cursor,end:piece.start});
   spans.push({kind:'clip',...piece});cursor=Math.max(cursor,piece.end);
 }
 if(cursor<duration)spans.push({kind:'skipped',start:cursor,end:duration});
 return spans;
}
export function timelineStats(clips,duration){
 const raw=timelinePieces(clips,duration);
 const kept=raw.filter(x=>x.kind==='clip'),merged=[];
 for(const piece of kept){
  if(merged.length&&merged.at(-1).end>=piece.start)
   merged.at(-1).end=Math.max(merged.at(-1).end,piece.end);
  else merged.push({start:piece.start,end:piece.end});
 }
 const keptSeconds=merged.reduce((sum,x)=>sum+x.end-x.start,0);
 return {duration,keptSeconds,skippedSeconds:Math.max(0,duration-keptSeconds),
  percent:duration>0?Math.round(100*keptSeconds/duration):0,
  clips:(clips||[]).filter(c=>c?.id!=='draft-1'&&sourceSegments(c).length).length,
  pieces:kept.length};
}
export function timelineTimeAtFraction(x,duration){
 return Math.max(0,Math.min(duration,Number.isFinite(x)?x*duration:0));
}
export function amendClipBoundary(clip,edge,newTime,duration,segmentIndex=null){
 if(!clip||!Number.isFinite(newTime)||!Number.isFinite(duration)||duration<=0)
  throw Error('Invalid timeline boundary');
 const pieces=sourceSegments(clip).map(p=>({...p}));
 const idx=segmentIndex===null?(edge==='start'?0:pieces.length-1):segmentIndex;
 if(!pieces[idx])throw Error('Unknown source piece');
 const target=pieces[idx];
 if(edge==='start')target.start=Math.max(0,Math.min(newTime,target.end-.5));
 else if(edge==='end')target.end=Math.min(duration,Math.max(newTime,target.start+.5));
 else throw Error('Unknown boundary');
 if(target.start<0||target.end>duration||target.end-target.start<.5)
  throw Error('Clip duration invalid');
 const start=Math.min(...pieces.map(p=>p.start)),end=Math.max(...pieces.map(p=>p.end));
 return {...clip,start,end,segments:pieces,status:'needs-review',approvedAt:undefined,llmReview:undefined,
   scene:undefined,reviewReasons:['Границы изменены на таймлайне; проверьте содержимое и пересоберите композицию.']};
}
export function appendSourceSegment(clip,start,end,duration){
 if(!clip||!Number.isFinite(start)||!Number.isFinite(end)||end-start<.5||start<0||end>duration)
  throw Error('Invalid source segment');
 const segments=[...sourceSegments(clip),{start,end}];
 return {...clip,segments,start:Math.min(...segments.map(s=>s.start)),end:Math.max(...segments.map(s=>s.end)),
  status:'needs-review',approvedAt:undefined,scene:undefined,llmReview:undefined,
  reviewReasons:['Несмежный фрагмент добавлен вручную — проверьте переход и связность объяснения']};
}
export function reorderSourceSegments(clip,index,direction){
 const pieces=sourceSegments(clip);
 const to=index+direction;if(index<0||index>=pieces.length||to<0||to>=pieces.length)throw Error('Invalid reorder');
 const swapped=[...pieces];[swapped[index],swapped[to]]=[swapped[to],swapped[index]];
 return {...clip,segments:swapped,status:'needs-review',approvedAt:undefined,scene:undefined,llmReview:undefined};
}
export function removeSourceSegment(clip,index){
 const pieces=sourceSegments(clip);
 if(pieces.length<=1||index<0||index>=pieces.length)throw Error('At least one segment is required');
 pieces.splice(index,1);
 return {...clip,segments:pieces,start:Math.min(...pieces.map(s=>s.start)),end:Math.max(...pieces.map(s=>s.end)),
  status:'needs-review',approvedAt:undefined,scene:undefined,llmReview:undefined};
}
