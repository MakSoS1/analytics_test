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
export function renderMicrotopicCatalog(container,clips,chunks,{selected=0,onSelect,onPlay,onEdit}={}){
 container.replaceChildren();
 if(!clips?.length){
   container.append(el('p','catalog-empty','Микротемы появятся после анализа полной расшифровки лекции.'));
   return;
 }
 const scroll=el('div','catalog-scroll');
 const table=el('table','microtopic-table');
 table.setAttribute('aria-label','Список микротем: сценарий, исходные таймкоды, расшифровка, видео');
 const head=el('thead'),headRow=el('tr');
 for(const title of ['№','Короткое название','Исходные фрагменты','Сценарий из речи','Расшифровка оригинала','Видео']){
   headRow.append(el('th','',title));
 }
 head.append(headRow);table.append(head);
 const body=el('tbody');
 clips.forEach((clip,i)=>{
   const topic=topicSummary(clip,chunks);
   const tr=el('tr',selected===i?'selected':'');
   tr.dataset.topicIndex=String(i);
   tr.append(el('td','catalog-index',String(i+1).padStart(2,'0')));
   const titleCell=el('td','catalog-title');
   const titleBtn=el('button','catalog-title-button',topic.title);
   titleBtn.type='button';titleBtn.onclick=()=>onSelect?.(i);
   titleCell.append(titleBtn,
      el('small','catalog-duration',time(topic.duration)+' · '+(topic.status==='approved'?'Проверено':'Черновик')));
   tr.append(titleCell);
   const sourceCell=el('td','catalog-source');
   for(const piece of topic.pieces)sourceCell.append(el('div','catalog-range',sourceRange(piece)));
   tr.append(sourceCell);
   const scriptCell=el('td','catalog-script');
   evidenceLines(scriptCell,topic.screenplay,b=>(roleName[b.role]||'Объяснение')+': '+b.quote,
     {preview:3,label:'Развернуть весь сценарий'});
   if(!topic.finished)scriptCell.append(el('small','catalog-warning','Концовка требует проверки'));
   tr.append(scriptCell);
   const transcriptCell=el('td','catalog-transcript');
   evidenceLines(transcriptCell,topic.spoken,c=>c.text,
     {preview:2,label:'Вся расшифровка с таймкодами'});
   tr.append(transcriptCell);
   const actionCell=el('td','catalog-actions');
   const play=el('button','catalog-play','▶ Смотреть 9:16');
   play.type='button';play.onclick=()=>onPlay?.(i);
   const edit=el('button','catalog-edit','Изменить');
   edit.type='button';edit.onclick=()=>onEdit?.(i);
   actionCell.append(play,edit);
   tr.append(actionCell);body.append(tr);
 });
 table.append(body);scroll.append(table);container.append(scroll);
}
