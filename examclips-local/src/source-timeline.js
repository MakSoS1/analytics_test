/** Pure source timeline model: every second is either in one/more clips or skipped.
 * The original file stays unchanged; re-cutting is reversible project metadata.
 */
export function timelinePieces(clips,duration){
 if(!Number.isFinite(duration)||duration<=0)return [];
 const intervals=(clips||[]).filter(c=>c&&c.id!=='draft-1'&&Number.isFinite(c.start)&&Number.isFinite(c.end))
  .map(c=>({id:c.id,title:c.title||'Фрагмент',start:Math.max(0,Math.min(duration,c.start)),
    end:Math.max(0,Math.min(duration,c.end)),status:c.status||'needs-review'}))
  .filter(x=>x.end>x.start).sort((a,b)=>a.start-b.start||a.end-b.end);
 const spans=[];let cursor=0;
 for(const c of intervals){
   if(c.start>cursor+1e-4)spans.push({kind:'skipped',start:cursor,end:c.start});
   spans.push({kind:'clip',...c});
   cursor=Math.max(cursor,c.end);
 }
 if(cursor<duration)spans.push({kind:'skipped',start:cursor,end:duration});
 return spans;
}
export function timelineStats(clips,duration){
 const raw=timelinePieces(clips,duration);
 const kept=raw.filter(x=>x.kind==='clip');
 const merge=[];
 for(const c of kept){
   if(merge.length&&merge.at(-1).end>=c.start)merge.at(-1).end=Math.max(merge.at(-1).end,c.end);
   else merge.push({start:c.start,end:c.end});
 }
 const keptSeconds=merge.reduce((sum,x)=>sum+x.end-x.start,0);
 return {duration,keptSeconds,skippedSeconds:Math.max(0,duration-keptSeconds),
  percent:duration>0?Math.round(100*keptSeconds/duration):0,clips:kept.length};
}
export function timelineTimeAtFraction(x,duration){
 return Math.max(0,Math.min(duration,Number.isFinite(x)?x*duration:0));
}
export function amendClipBoundary(clip,edge,newTime,duration){
 if(!clip||!Number.isFinite(newTime)||!Number.isFinite(duration)||duration<=0)throw Error('Invalid timeline boundary');
 let a=clip.start,b=clip.end;
 if(edge==='start')a=Math.max(0,Math.min(newTime,b-.5));
 else if(edge==='end')b=Math.min(duration,Math.max(newTime,a+.5));
 else throw Error('Unknown boundary');
 if(a<0||b>duration||b-a<.5)throw Error('Clip duration invalid');
 return {...clip,start:a,end:b,status:'needs-review',approvedAt:undefined,llmReview:undefined,
   scene:undefined,reviewReasons:['Границы изменены на таймлайне; проверьте содержимое и повторно создайте композицию.']};
}
