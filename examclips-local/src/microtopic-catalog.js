/**
 * Explainable topic catalogue. Every quote and timestamp comes from the
 * original ASR/SRT, not generated narration. Video is previewed by the
 * existing 9:16 compositor; these rows are draft edits until MP4 export.
 */
import {sourceSegments,storyDuration} from './selective-stories.js';
import {inferEditorialBeats} from './lesson-screenplay.js';
export function sourceCues(clip,chunks){
 const pieces=sourceSegments(clip);
 return (chunks||[]).filter(c=>pieces.some(p=>c.end>p.start&&c.start<p.end))
   .map(c=>({start:c.start,end:c.end,text:String(c.text||'').trim()}))
   .filter(c=>c.text);
}
export function topicSummary(clip,chunks){
 const pieces=sourceSegments(clip);
 const spoken=sourceCues(clip,chunks);
 const screenplay=clip.screenplay?.beats?.length?
   clip.screenplay.beats:inferEditorialBeats(clip,chunks);
 return {title:String(clip.title||'Микротема без названия'),pieces,
   spoken,screenplay,duration:storyDuration(clip),
   finished:!!clip.screenplay?.quality?.finished,
   status:clip.status||'needs-review'};
}
const time=s=>{
 const n=Math.max(0,Math.floor(Number(s)||0)),h=Math.floor(n/3600);
 return [h,Math.floor(n%3600/60),n%60].map(x=>String(x).padStart(2,'0')).join(':');
};
export const sourceRange=p=>time(p.start)+'–'+time(p.end);
function el(tag,cls,txt){
 const node=document.createElement(tag);
 if(cls)node.className=cls;
 if(txt!==undefined)node.textContent=String(txt);
 return node;
}
function evidenceLines(cell,items,formatter,{preview=3,label='Показать все'}={}){
 if(!items.length){
   cell.append(el('p','catalog-empty','Расшифровка пока отсутствует — импортируйте SRT или запустите Whisper.'));
   return;
 }
 const put=(parent,lines)=>{
   const list=el('ol','catalog-lines');
   for(const item of lines){
     const li=el('li');
     li.append(el('time','catalog-time',time(item.start)),el('span','',formatter(item)));
     list.append(li);
   }
   parent.append(list);
 };
 put(cell,items.slice(0,preview));
 if(items.length>preview){
   const details=el('details','catalog-expand');
   const summary=el('summary','',label+' ('+items.length+')');
   details.append(summary);
   const expanded=el('div','catalog-expanded');
   put(expanded,items);details.append(expanded);cell.append(details);
 }
}
const roleName={intro:'Тезис',explanation:'Объяснение',takeaway:'Вывод'};
/** Chapter-ordered media gallery, replacing the unscannable six-column table. */
export function renderMicrotopicCatalog(container,clips,chunks,{
 selected=0,onSelect,onPlay,onEdit,thumbnails=new Map()
}={}){
 container.replaceChildren();
 if(!clips?.length){
  container.append(el('p','catalog-empty','Микротемы появятся после анализа полной расшифровки лекции.'));
  return;
 }
 const grid=el('div','microtopic-grid');
 grid.setAttribute('role','list');
 grid.setAttribute('aria-label','Учебные микротемы по порядку');
 clips.forEach((clip,i)=>{
  const topic=topicSummary(clip,chunks);
  const card=el('article','microtopic-card'+(i===selected?' selected':''));
  card.dataset.topicIndex=String(i);
  card.setAttribute('role','listitem');
  const thumb=el('button','microtopic-cover');
  thumb.type='button';thumb.setAttribute('aria-label','Открыть: '+topic.title);
  const src=thumbnails.get(clip.id);
  if(src){
    const img=el('img','microtopic-cover-image');
    img.src=src;img.alt='Кадр исходной лекции: '+topic.title;
    img.loading='lazy';
    thumb.append(img);
  }else{
    const placeholder=el('span','microtopic-cover-placeholder','▶');
    thumb.append(placeholder);
  }
  const stamp=el('span','microtopic-cover-timestamp',time(topic.pieces[0]?.start??clip.start));
  thumb.append(stamp);thumb.onclick=()=>onSelect?.(i);
  card.append(thumb);
  const info=el('div','microtopic-card-content');
  const row=el('div','microtopic-card-overline');
  row.append(el('span','microtopic-card-number','Тема '+(i+1)),
    el('span','microtopic-card-time',time(topic.duration)));
  info.append(row);
  const open=el('button','microtopic-card-title',topic.title);
  open.type='button';open.onclick=()=>onSelect?.(i);info.append(open);
  const chapter=clip.chapter?.title;
  if(chapter)info.append(el('p','microtopic-card-chapter',chapter));
  const quality=clip.screenplay?.quality;
  const label=quality?.fullySupported?'Есть подтверждённый итог':
    quality?.readyForReview?'Проверьте завершённость':'Недостаточно доказательств';
  info.append(el('small','microtopic-card-status',label));
  card.append(info);grid.append(card);
 });
 container.append(grid);
}
export function renderMicrotopicDetail(container,clip,chunks){
 if(!container)return;
 container.replaceChildren();
 if(!clip)return;
 const topic=topicSummary(clip,chunks);
 const heading=el('div','microtopic-detail-summary');
 heading.append(el('p','microtopic-detail-eyebrow',clip.chapter?.title||'Самостоятельная микротема'),
  el('h2','',topic.title));
 const timeBox=el('p','microtopic-detail-range','Исходная запись: '+topic.pieces.map(sourceRange).join(' · '));
 heading.append(timeBox);
 const quality=clip.screenplay?.quality;
 heading.append(el('p','microtopic-quality',quality?.fullySupported?
  'Есть подтверждённые объяснения и вывод':
  'Требуется проверка: речь не подтверждает полностью завершённый ответ'));
 container.append(heading);
 const script=el('section','microtopic-detail-script');
 script.append(el('h3','','Краткий сценарий · подтверждённый исходной речью'));
 const summary=clip.screenplay?.summary||[];
 if(!summary.length)script.append(el('p','catalog-empty','Сначала распознайте всю речь.'));
 for(const item of summary){
   const row=el('article','microtopic-summary-item');
   row.append(el('strong','',item.label||'Тезис'));
   row.append(el('p','microtopic-summary-text',item.text));
   for(const proof of item.evidence||[]){
     const details=el('details','microtopic-proof');
     details.append(el('summary','','Источник '+sourceRange(proof)));
     details.append(el('blockquote','',proof.quote));
     row.append(details);
   }
   script.append(row);
 }
 container.append(script);
 const transcript=el('section','microtopic-detail-transcript');
 transcript.append(el('h3','','Расшифровка и оригинальные таймкоды'));
 const transcriptBody=el('div','microtopic-transcript-lines');
 evidenceLines(transcriptBody,topic.spoken,c=>c.text,{preview:6,label:'Развернуть весь оригинал'});
 transcript.append(transcriptBody);container.append(transcript);
}
