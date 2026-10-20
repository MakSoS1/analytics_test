/**
 * Local transparent coverage check: compare frame-inspected educational
 * checkpoints with ASR source intervals actually selected by video EDL.
 * Not a semantic guarantee: these are leads for reviewing omissions/overmerge.
 */
import {sourceSegments} from './selective-stories.js';
const speechSeconds=r=>Math.max(0,r.end-r.start);
const overlap=(a,b)=>Math.max(0,Math.min(a.end,b.end)-Math.max(a.start,b.start));
export function inspectLectureCoverage(hints,clips,chunks){
 const results=(hints||[]).map(h=>{
  const rows=(chunks||[]).filter(r=>overlap(r,h)>0&&String(r.text||'').trim());
  const words=rows.reduce((n,r)=>n+(r.text.match(/[\p{L}\p{N}]+/gu)||[]).length,0);
  const speech=rows.reduce((n,r)=>n+overlap(r,h),0);
  const supported=rows.filter(r=>h.terms?.test(r.text));
  const owners=(clips||[]).map((c,i)=>{
   const intersections=sourceSegments(c).reduce((n,s)=>n+overlap(s,h),0);
   return {index:i+1,clip:c,seconds:intersections,sourceSeconds:sourceSegments(c).reduce((n,s)=>n+speechSeconds(s),0)};
  }).filter(o=>o.seconds>=8);
  const totalVideo=owners.reduce((n,x)=>n+x.seconds,0);
  const spokenCovered=rows.filter(r=>owners.some(o=>sourceSegments(o.clip).some(s=>overlap(s,r)>.5)))
    .reduce((n,r)=>n+overlap(r,h),0);
  const sufficientSpeech=speech>=22&&words>=28;
  const dedicated=owners.find(o=>h.id&&o.clip.visualSection===h.id&&
    o.seconds>=Math.min(30,speech*.5));
  const shared=owners.some(o=>o.sourceSeconds>Math.max(180,(h.end-h.start)*1.7));
  const status=!sufficientSpeech?'insufficient-transcript':
     !owners.length||spokenCovered<speech*.3?'not-in-clips':
     dedicated?'separate-video':
     shared?'merged-into-chapter':'needs-review';
  return {id:h.id,title:h.title,start:h.start,end:h.end,
   chapterKey:h.chapterKey,spokenSeconds:+speech.toFixed(1),words,
   spokenCues:supported.length,videoCount:owners.length,
   videoIndices:owners.map(o=>o.index),
   videoCoveredSeconds:+totalVideo.toFixed(1),status,
   sourceKind:h.evidenceKind};
 });
 return {rows:results,summary:{
  observed:results.length,
  separate:results.filter(r=>r.status==='separate-video').length,
  merged:results.filter(r=>r.status==='merged-into-chapter').length,
  lost:results.filter(r=>r.status==='not-in-clips').length,
  unconfirmed:results.filter(r=>r.status==='insufficient-transcript').length
 }};
}
export function renderLectureCoverage(element,hints,clips,chunks){
 if(!element)return;
 element.replaceChildren();
 if(!hints?.length)return;
 const review=inspectLectureCoverage(hints,clips,chunks);
 const box=document.createElement('section');box.className='microtopic-coverage-review';
 const h=document.createElement('h3');h.textContent='Проверка покрытия лекции по исходным слайдам';
 box.append(h);
 const p=document.createElement('p');p.className='muted';
 p.textContent='В оригинале отмечено '+review.summary.observed+' потенциальных подтем: '+
   review.summary.separate+' отдельно выделено, '+review.summary.merged+
   ' находятся в общих длинных видео, '+review.summary.lost+' могли выпасть, '+
   review.summary.unconfirmed+' не подтверждены достаточной речью. '+
   'Это контроль по кадрам и таймкодам, не доказательство полноты сценария.';
 box.append(p);
 const table=document.createElement('table');table.className='coverage-check-table';
 const thead=document.createElement('thead');const tr=document.createElement('tr');
 for(const label of ['Подтема исходной лекции','Фрагмент','Видео','Что проверить']){
  const th=document.createElement('th');th.textContent=label;tr.append(th);
 }
 thead.append(tr);table.append(thead);
 const tbody=document.createElement('tbody');
 const time=second=>{const n=Math.floor(second);return [Math.floor(n/3600),Math.floor(n/60)%60,n%60].map(x=>String(x).padStart(2,'0')).join(':')};
 const status={
  'separate-video':'Отдельный ролик',
  'merged-into-chapter':'Слито в большой ролик',
  'not-in-clips':'Возможно пропущено',
  'insufficient-transcript':'Недостаточно расшифровки',
  'needs-review':'Проверить границы'
 };
 for(const item of review.rows){
  const tr=document.createElement('tr');tr.dataset.status=item.status;
  for(const value of [item.title,time(item.start)+'–'+time(item.end),
   item.videoIndices.length?item.videoIndices.join(', '):'—',status[item.status]]){
   const td=document.createElement('td');td.textContent=value;tr.append(td);
  }
  tbody.append(tr);
 }
 table.append(tbody);box.append(table);element.append(box);
}
