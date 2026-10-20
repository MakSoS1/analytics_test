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
const shortTime=s=>{
 const n=Math.max(0,Math.round(Number(s)||0)),h=Math.floor(n/3600);
 const m=String(Math.floor(n%3600/60)).padStart(h?2:1,'0');
 return (h?h+':':'')+m+':'+String(n%60).padStart(2,'0');
};
const shortRange=p=>shortTime(p.start)+'–'+shortTime(p.end);
function seekTime(start,onSeek,{end}={}){
 const enabled=typeof onSeek==='function'&&Number.isFinite(start);
 const node=el(enabled?'button':'time','catalog-time',time(start));
 if(enabled){
  node.type='button';
  node.setAttribute('aria-label','Перейти к '+time(start)+' исходной лекции');
  node.onclick=()=>onSeek(start);
 }
 if(Number.isFinite(end))node.title='Исходный отрывок: '+sourceRange({start,end});
 return node;
}
function evidenceLines(cell,items,formatter,{preview=3,label='Показать все',onSeek}={}){
 if(!items.length){
   cell.append(el('p','catalog-empty','Расшифровка пока отсутствует — импортируйте SRT или запустите Whisper.'));
   return;
 }
 const put=(parent,lines)=>{
   const list=el('ol','catalog-lines');
   for(const item of lines){
     const li=el('li');
     li.append(seekTime(item.start,onSeek,item),el('span','catalog-transcript-text',formatter(item)));
     list.append(li);
   }
   parent.append(list);
 };
 put(cell,items.slice(0,preview));
 if(items.length>preview){
   const details=el('details','catalog-expand');
   const summary=el('summary','',label+' · ещё '+(items.length-preview));
   details.append(summary);
   const expanded=el('div','catalog-expanded');
   put(expanded,items.slice(preview));details.append(expanded);cell.append(details);
 }
}
function clipState(clip){
 if(clip.candidate)return {key:'candidate',label:'Кандидат',step:1};
 if(clip.status==='approved')return {key:'approved',label:'Проверено',step:2};
 if(clip.status==='needs-review'||clip.editorialStatus==='needs-more-context')
  return {key:'needs-review',label:'Проверить',step:1};
 return {key:'found',label:'Найдено',step:1};
}
function statusMeter(clip){
 const state=clipState(clip),status=el('span','microtopic-card-status');
 status.dataset.status=state.key;
 status.setAttribute('aria-label','Статус: '+state.label);
 const bars=el('span','microtopic-status-meter');bars.setAttribute('aria-hidden','true');
 for(let i=0;i<3;i++)bars.append(el('span',i<state.step?'filled':''));
 status.append(bars,el('span','microtopic-status-label',state.label));
 return status;
}
function chapterInfo(clip){
 const chapter=clip.chapter;
 const title=typeof chapter==='string'?chapter:chapter?.title;
 return {title:title||'Учебные темы',
  key:typeof chapter==='object'&&chapter!==null
   ? String(chapter.id??chapter.start??'')+'|'+(title||'Учебные темы')
   : title||'Учебные темы'};
}
function originalStart(clip){
 const starts=sourceSegments(clip).map(p=>p.start).filter(Number.isFinite);
 return starts.length?Math.min(...starts):Number(clip.start)||0;
}
function cardSummary(clip,topic){
 const summary=Array.isArray(clip.screenplay?.summary)?clip.screenplay.summary:[];
 return summary.map(item=>String(item.text||'').trim()).filter(Boolean).join(' ')
  ||topic.spoken[0]?.text||'Для описания урока нужна расшифровка.';
}
function renderCard({clip,index},chunks,{selected,onSelect,onPlay,onEdit,thumbnails,onAccept,onReject}){
 const topic=topicSummary(clip,chunks);
 const card=el('article','microtopic-card'+(index===selected?' selected':'')+(clip.candidate?' is-candidate':''));
 card.dataset.topicIndex=String(index);card.dataset.clipId=String(clip.id||'');
 card.setAttribute('role','listitem');
 const openTopic=onSelect||onEdit||onPlay;
 const open=()=>openTopic?.(index);
 const thumb=el('button','microtopic-cover');
 thumb.type='button';thumb.setAttribute('aria-label','Открыть урок: '+topic.title);
 thumb.disabled=typeof openTopic!=='function';thumb.onclick=open;
 const src=thumbnails.get(clip.id);
 if(src){
  const img=el('img','microtopic-cover-image');
  img.src=src;img.alt='Вертикальная обложка урока «'+topic.title+'» из исходной записи';
  img.loading='lazy';img.decoding='async';img.width=360;img.height=640;
  thumb.append(img);
 }else{
  const placeholder=el('span','microtopic-cover-placeholder');
  placeholder.append(el('span','microtopic-placeholder-format','9:16'),
   el('span','microtopic-placeholder-label','Обложка ещё не готова'));
  thumb.append(placeholder);
 }
 const duration=el('span','microtopic-cover-timestamp microtopic-card-time',shortTime(topic.duration));
 duration.setAttribute('aria-label','Длительность урока: '+time(topic.duration));
 thumb.append(duration);card.append(thumb);
 const info=el('div','microtopic-card-content');
 const title=el('button','microtopic-card-title',topic.title);
 title.type='button';title.disabled=typeof openTopic!=='function';title.onclick=open;
 title.setAttribute('aria-label','Открыть урок: '+topic.title);
 info.append(title,el('p','microtopic-card-summary',cardSummary(clip,topic)));
 const footer=el('div','microtopic-card-footer');
 const ranges=el('span','microtopic-card-ranges');
 ranges.setAttribute('aria-label','Исходные отрывки: '+topic.pieces.map(sourceRange).join(', '));
 ranges.title=topic.pieces.map(sourceRange).join(' · ');
 for(const piece of topic.pieces)ranges.append(el('span','microtopic-card-range',shortRange(piece)));
 footer.append(ranges,statusMeter(clip));info.append(footer);card.append(info);
 if(clip.candidate){
  const actions=el('div','microtopic-candidate-actions');
  const accept=el('button','microtopic-accept','✓ Принять');
  accept.type='button';accept.disabled=typeof onAccept!=='function';
  accept.setAttribute('aria-label','Принять кандидата: '+topic.title);
  accept.onclick=()=>onAccept?.(index);
  const reject=el('button','microtopic-reject','✕');
  reject.type='button';reject.disabled=typeof onReject!=='function';
  reject.setAttribute('aria-label','Отклонить кандидата: '+topic.title);
  reject.title='Отклонить кандидата';reject.onclick=()=>onReject?.(index);
  actions.append(accept,reject);card.append(actions);
 }
 return card;
}
function cardSection(title,items,chunks,options,{candidate=false}={}){
 const section=el('section','microtopic-chapter'+(candidate?' microtopic-candidates':''));
 section.setAttribute('aria-label',title);
 const header=el('div','microtopic-chapter-header');
 header.append(el('h3','microtopic-chapter-heading',title));
 const pieces=items.flatMap(({clip})=>sourceSegments(clip));
 const start=Math.min(...pieces.map(p=>p.start)),end=Math.max(...pieces.map(p=>p.end));
 const range=Number.isFinite(start)&&Number.isFinite(end)?' · '+shortRange({start,end}):'';
 header.append(el('span','microtopic-chapter-meta',String(items.length)+range));
 section.append(header);
 const grid=el('div','microtopic-grid');
 grid.setAttribute('role','list');grid.setAttribute('aria-label',candidate?'Кандидаты в микроуроки':'Микроуроки: '+title);
 for(const item of items)grid.append(renderCard(item,chunks,options));
 section.append(grid);return section;
}
/** Portrait gallery. Display order never changes the indices received by callers. */
export function renderMicrotopicCatalog(container,clips,chunks,{
 selected=0,onSelect,onPlay,onEdit,thumbnails=new Map(),onAccept,onReject
}={}){
 if(!container)return;
 container.replaceChildren();
 const entries=(clips||[]).map((clip,index)=>({clip,index}))
  .filter(({clip})=>clip&&clip.id!=='draft-1')
  .sort((a,b)=>originalStart(a.clip)-originalStart(b.clip)||a.index-b.index);
 if(!entries.length){
  container.append(el('p','catalog-empty','Микротемы появятся после анализа полной расшифровки лекции.'));
  return;
 }
 const options={selected,onSelect,onPlay,onEdit,thumbnails:thumbnails||new Map(),onAccept,onReject};
 const gallery=el('div','microtopic-chapters atlas-catalog');
 const candidates=entries.filter(({clip})=>clip.candidate);
 if(candidates.length)gallery.append(cardSection('Кандидаты — проверьте и примите',candidates,chunks,options,{candidate:true}));
 const chapters=new Map();
 for(const entry of entries.filter(({clip})=>!clip.candidate)){
  const chapter=chapterInfo(entry.clip);
  if(!chapters.has(chapter.key))chapters.set(chapter.key,{title:chapter.title,items:[]});
  chapters.get(chapter.key).items.push(entry);
 }
 for(const chapter of chapters.values())gallery.append(cardSection(chapter.title,chapter.items,chunks,options));
 container.append(gallery);
}
export function renderMicrotopicDetail(container,clip,chunks,{onSeek}={}){
 if(!container)return;
 container.replaceChildren();
 if(!clip)return;
 const topic=topicSummary(clip,chunks);
 const quality=clip.screenplay?.quality;
 const panels=el('div','atlas-evidence-grid');
 const script=el('section','microtopic-detail-script');
 script.setAttribute('aria-label','Суть урока');script.append(el('h3','atlas-evidence-heading','Суть урока'));
 const summary=Array.isArray(clip.screenplay?.summary)?clip.screenplay.summary:[];
 if(!summary.length)script.append(el('p','catalog-empty',topic.spoken.length
  ?'Сценарий ещё не подготовлен. Исходные реплики доступны в расшифровке ниже.'
  :'Для сценария нужна расшифровка лекции. Импортируйте SRT или запустите Whisper.'));
 const proofs=[],seen=new Set();
 for(const item of summary){
   const row=el('article','microtopic-summary-item');
   row.append(el('strong','',item.label||'Тезис'));
   row.append(el('p','microtopic-summary-text',item.text||''));
   for(const proof of Array.isArray(item.evidence)?item.evidence:[]){
     if(!Number.isFinite(proof.start)||!String(proof.quote||'').trim())continue;
     const key=[proof.start,proof.end,proof.quote].join('|');
     if(!seen.has(key)){seen.add(key);proofs.push(proof);}
   }
   script.append(row);
 }
 if(!quality?.fullySupported&&summary.length)script.append(el('p','microtopic-quality',
  'Проверьте, что объяснение и вывод подтверждены исходной речью.'));
 const evidence=el('section','microtopic-detail-evidence');
 evidence.setAttribute('aria-label','Цитаты-доказательства');
 evidence.append(el('h3','atlas-evidence-heading','Цитаты-доказательства'));
 if(!proofs.length)evidence.append(el('p','catalog-empty','Цитаты появятся после подготовки сценария по исходной расшифровке.'));
 const quotes=el('ol','microtopic-proof-list');
 for(const proof of proofs.sort((a,b)=>a.start-b.start)){
  const row=el('li','microtopic-proof');
  row.append(seekTime(proof.start,onSeek,proof),el('blockquote','',proof.quote));
  quotes.append(row);
 }
 evidence.append(quotes);panels.append(script,evidence);container.append(panels);
 const transcript=el('section','microtopic-detail-transcript atlas-transcript');
 transcript.append(el('h3','atlas-evidence-heading','Расшифровка и оригинальные таймкоды'));
 transcript.append(el('p','microtopic-detail-range','Исходные отрывки: '+topic.pieces.map(sourceRange).join(' · ')));
 const transcriptBody=el('div','microtopic-transcript-lines');
 evidenceLines(transcriptBody,topic.spoken,c=>c.text,{preview:6,label:'Развернуть весь оригинал',onSeek});
 transcript.append(transcriptBody);container.append(transcript);
}
