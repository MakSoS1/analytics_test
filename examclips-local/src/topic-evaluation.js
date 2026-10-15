/**
 * Offline microtopic evaluation. Requires independent HUMAN reference intervals.
 * Does not generate fake benchmark scores when the reference set is empty.
 */
export function evaluateTopics(predicted,gold,{tolerance=10}={}){
 if(!Array.isArray(predicted)||!Array.isArray(gold)||gold.length===0)
   throw Error('Required: a nonempty human-annotated reference set');
 const take=xs=>xs.flatMap(c=>[c.start,c.end]).filter(Number.isFinite).sort((a,b)=>a-b);
 const predictions=take(predicted),references=take(gold);
 const used=new Set(),matches=[];
 for(const p of predictions){
   let best=-1,diff=Infinity;
   for(let j=0;j<references.length;j++){
     const d=Math.abs(references[j]-p);
     if(!used.has(j)&&d<=tolerance&&d<diff){best=j;diff=d}
   }
   if(best>=0){used.add(best);matches.push(diff)}
 }
 const tp=matches.length,precision=predictions.length?tp/predictions.length:0;
 const recall=references.length?tp/references.length:0;
 const f1=precision+recall?2*precision*recall/(precision+recall):0;
 return {references:gold.length,predicted:predicted.length,
  matchedBoundaries:tp,totalCandidateBoundaries:predictions.length,
  totalReferenceBoundaries:references.length,
  precision,recall,f1,meanBoundaryErrorSeconds:tp?matches.reduce((a,b)=>a+b,0)/tp:null,
  toleranceSeconds:tolerance,
  note:'These are boundary metrics only, not pedagogical completeness or ASR WER.'};
}
export function approvedAnnotations(project){
 if(!project||!Array.isArray(project.clips))return [];
 return project.clips.filter(c=>c.status==='approved'&&Number.isFinite(c.start)&&Number.isFinite(c.end)
   &&c.start>=0&&c.end>c.start)
  .map(c=>({start:c.start,end:c.end,title:c.title||'',approvedAt:c.approvedAt||null}));
}
