/** Read-only views of the engine's current project.
 * Timelines use original source seconds; segment order is never changed here.
 * This module owns labels and display nodes, not media, edits, or persistence.
 */
import {coverageSpans} from './atlas-range.js';
import {sourceSegments,storyDuration} from './selective-stories.js';

const $=id=>typeof document==='undefined'?null:document.getElementById(id);
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));
const number=value=>Number.isFinite(Number(value))?Number(value):0;
const text=(id,value)=>{const node=$(id);if(node)node.textContent=String(value)};
const disabled=(id,value)=>{const node=$(id);if(node)node.disabled=!!value};
const node=(tag,className,label)=>{
 const result=document.createElement(tag);
 if(className)result.className=className;
 if(label!==undefined)result.textContent=String(label);
 return result;
};
function stamp(value,precise=false){
 const seconds=Math.max(0,number(value));
 const whole=Math.floor(seconds),hours=Math.floor(whole/3600);
 const minutes=String(Math.floor(whole%3600/60)).padStart(2,'0');
 const rest=String(whole%60).padStart(2,'0');
 const fraction=precise?'.'+String(Math.floor((seconds-whole)*10+.0001)):'';
 return (hours?hours+':':'')+minutes+':'+rest+fraction;
}
const spanLabel=piece=>stamp(piece.start)+'–'+stamp(piece.end);
function partsFor(clip,duration){
 if(!clip||!(duration>0))return [];
 return sourceSegments(clip).map((piece,index)=>({
  start:clamp(number(piece.start),0,duration),
  end:clamp(number(piece.end),0,duration),index
 })).filter(piece=>piece.end>piece.start);
}
function position(element,start,end,from,to){
 const width=Math.max(.001,to-from);
 element.style.left=(100*(start-from)/width)+'%';
 element.style.width=(100*Math.max(0,end-start)/width)+'%';
}
function ruler(id,from,to,count=5){
 const mount=$(id);if(!mount)return;
 const labels=Array.from({length:count},(_,i)=>
  node('span','',stamp(from+(to-from)*i/(count-1))));
 mount.replaceChildren(...labels);
}
function selectionFor(selection,duration){
 if(!selection||!(duration>0))return null;
 const start=Number(selection.start),end=Number(selection.end);
 if(!Number.isFinite(start)||!Number.isFinite(end))return null;
 return {start:clamp(Math.min(start,end),0,duration),
  end:clamp(Math.max(start,end),0,duration)};
}

let currentView={pieces:[],hasMedia:false,hasClip:false,busy:false,duration:0};

function renderCoverage(clips,chunks,duration,busy,rangeSelection){
 const report=coverageSpans(clips,duration);
 const real=clips.filter(clip=>clip&&clip.id!=='draft-1'&&!clip.candidate&&partsFor(clip,duration).length);
 const candidates=clips.filter(clip=>clip&&clip.id!=='draft-1'&&clip.candidate);
 text('atlas-stat-clips',real.length);
 text('atlas-stat-coverage',Math.round(report.percent)+'%');
 text('atlas-stat-ready',real.filter(clip=>clip.status==='approved').length+'/'+real.length);
 const track=$('atlas-coverage-track'),selection=$('atlas-range-selection');
 const range=selectionFor(rangeSelection,duration);
 if(track){
  // Keep the existing selection node: the shell owns range input gestures.
  track.querySelectorAll('.atlas-coverage-span').forEach(element=>element.remove());
  const fragment=document.createDocumentFragment();
  for(const piece of report.included){
   const included=node('div','atlas-coverage-span kept atlas-coverage-kept');
   position(included,piece.start,piece.end,0,duration);
   included.title='В микротемах: '+spanLabel(piece);
   included.setAttribute('aria-hidden','true');fragment.append(included);
  }
  for(const clip of candidates){
   for(const piece of partsFor(clip,duration)){
    const candidate=node('div','atlas-coverage-span candidate atlas-coverage-candidate');
    position(candidate,piece.start,piece.end,0,duration);
    candidate.title='Кандидат: '+String(clip.title||'Микротема')+' · '+spanLabel(piece);
    candidate.dataset.clipId=String(clip.id);
    candidate.setAttribute('aria-hidden','true');fragment.append(candidate);
   }
  }
  track.insertBefore(fragment,selection?.parentElement===track?selection:null);
  track.setAttribute('aria-valuemin','0');
  track.setAttribute('aria-valuemax',String(duration||1));
  track.setAttribute('aria-valuenow',String(range?.start??0));
  track.setAttribute('aria-valuetext',range?
   'Выбрано '+spanLabel(range)+', '+(range.end-range.start).toFixed(1)+' секунд':
   'Выберите участок исходной лекции для поиска тем');
  track.setAttribute('aria-disabled',String(busy||!(duration>0)));
 }
 ruler('atlas-coverage-ruler',0,duration);
 if(selection){
  selection.hidden=!range;
  if(range)position(selection,range.start,range.end,0,duration);
 }
 const actions=$('atlas-range-actions');if(actions)actions.hidden=!range;
 for(const [id,value] of [['atlas-range-start',range?.start],['atlas-range-end',range?.end]]){
  const field=$(id);
  if(field&&document.activeElement!==field)field.value=Number.isFinite(value)?value.toFixed(1):'';
  if(field)field.disabled=busy;
 }
 const usable=range&&range.end-range.start>=10;
 disabled('atlas-select-range',busy||!(duration>0));
 // Both actions work with a saved project's metadata. Discovery only needs
 // its transcript; attaching source video is required later for playback.
 disabled('atlas-range-find',busy||!usable||!chunks.length);
 disabled('atlas-range-create',busy||!usable);
 disabled('atlas-range-clear',busy);
 const find=$('atlas-range-find');
 if(find)find.title=!chunks.length?'Для поиска нужна сохранённая расшифровка или SRT':
  !usable?'Выберите не меньше 10 секунд исходной лекции':'Найти новые темы по сохранённой расшифровке';
 const create=$('atlas-range-create');
 if(create)create.title=!usable?'Выберите не меньше 10 секунд исходной лекции':
  'Создать черновик из выбранного участка и проверить его';
}

function renderLocalTimeline(clip,pieces,duration,busy,hasMedia){
 const track=$('atlas-local-track');if(!track)return;
 const focused=document.activeElement?.closest?.('.atlas-local-handle');
 const focusKey=focused&&track.contains(focused)?
  {piece:focused.dataset.piece,edge:focused.dataset.edge}:null;
 let playhead=track.querySelector('.atlas-local-playhead');
 if(!playhead){playhead=node('div','atlas-local-playhead');track.append(playhead)}
 track.querySelectorAll('.atlas-local-segment').forEach(element=>element.remove());
 const from=pieces.length?Math.max(0,Math.min(...pieces.map(piece=>piece.start))-60):0;
 const to=pieces.length?Math.min(duration,Math.max(...pieces.map(piece=>piece.end))+60):duration;
 track.dataset.start=String(from);track.dataset.end=String(to);
 track.setAttribute('aria-label',pieces.length?
  'Исходная шкала микроурока: '+stamp(from)+'–'+stamp(to)+', отрывков '+pieces.length:
  'Выберите микроурок для просмотра его исходной шкалы');
 const fragment=document.createDocumentFragment();
 for(const piece of pieces){
  const section=node('div','atlas-local-segment');
  position(section,piece.start,piece.end,from,to);
  section.dataset.piece=String(piece.index);
  section.title='Часть '+(piece.index+1)+' в монтаже · '+spanLabel(piece);
  for(const edge of ['start','end']){
   const handle=node('button','atlas-local-handle '+edge);
   handle.type='button';handle.disabled=busy||!hasMedia;
   handle.dataset.piece=String(piece.index);handle.dataset.edge=edge;
   handle.dataset.time=String(piece[edge]);
   handle.setAttribute('role','slider');
   handle.setAttribute('aria-label',(edge==='start'?'Начало':'Конец')+' отрывка '+(piece.index+1));
   handle.setAttribute('aria-valuemin',String(edge==='start'?0:piece.start+.5));
   handle.setAttribute('aria-valuemax',String(edge==='start'?piece.end-.5:duration));
   handle.setAttribute('aria-valuenow',String(piece[edge]));
   handle.setAttribute('aria-valuetext',stamp(piece[edge],true));
   handle.title=(edge==='start'?'Начало':'Конец')+': '+stamp(piece[edge],true)+
    '. Тяните край или используйте ← / →, Shift — 10 секунд.';
   section.append(handle);
  }
  fragment.append(section);
 }
 track.insertBefore(fragment,playhead);
 ruler('atlas-local-ruler',from,to,3);
 playhead.hidden=!clip||!pieces.length;
 if(focusKey){
  const replacement=[...track.querySelectorAll('.atlas-local-handle')].find(handle=>
   handle.dataset.piece===focusKey.piece&&handle.dataset.edge===focusKey.edge);
  replacement?.focus({preventScroll:true});
 }
}

/** Render statistics and selection controls without modifying engine inputs. */
export function renderAtlasPanels({clips=[],chunks=[],duration=0,selected=0,media=null,busy=false,rangeSelection=null}={}){
 if(!$('atlas-coverage-track'))return;
 clips=Array.isArray(clips)?clips:[];chunks=Array.isArray(chunks)?chunks:[];
 duration=Math.max(0,number(duration));busy=!!busy;
 const clip=clips[selected]||null,pieces=partsFor(clip,duration);
 const hasClip=!!clip&&clip.id!=='draft-1'&&pieces.length>0;
 currentView={pieces,hasMedia:!!media,hasClip,busy,duration};
 renderCoverage(clips,chunks,duration,busy,rangeSelection);

 const chapter=typeof clip?.chapter==='string'?clip.chapter:clip?.chapter?.title;
 const ranges=pieces.map(spanLabel);
 const meta=hasClip?[chapter||'Самостоятельный микроурок',
  pieces.length>3?pieces.length+' отрывков':ranges.join(' · '),
  stamp(storyDuration(clip))+' в монтаже'].join(' · '):'Выберите микроурок';
 text('atlas-detail-meta',meta);
 const metaNode=$('atlas-detail-meta');if(metaNode)metaNode.title=ranges.join(' · ');
 const status=!hasClip?'':clip.candidate?'Кандидат — проверьте и примите':
  clip.status==='approved'?'✓ Проверено вручную':
  clip.editorialStatus==='needs-more-context'?'Требуется проверка границ':'Найдено · ожидает проверки';
 text('atlas-detail-status',status);
 const approve=$('approve-topic');
 if(approve){
  approve.hidden=!hasClip;
  approve.textContent=clip?.status==='approved'?'✓ Проверено · снять отметку':'Отметить проверенным ›';
  approve.setAttribute('aria-pressed',String(clip?.status==='approved'));
 }
 const accept=$('atlas-accept-current');
 if(accept){accept.hidden=!hasClip||!clip.candidate;accept.disabled=busy}
 const exported=$('export');
 disabled('atlas-export-clip',!hasClip||!exported||exported.disabled);

 // Match navigateAtlas(): source chronology, with candidates included and
 // the loading draft omitted. Preserve the engine's original array indices.
 const order=clips.map((clip,index)=>({clip,index}))
  .filter(({clip})=>clip&&clip.id!=='draft-1')
  .sort((a,b)=>a.clip.start-b.clip.start);
 const position=order.findIndex(item=>item.index===selected);
 const previous=order[position-1]?.clip,next=order[position+1]?.clip;
 text('atlas-detail-index',hasClip&&position>=0?(position+1)+' / '+order.length:'');
 disabled('atlas-previous',busy||!previous);disabled('atlas-next',busy||!next);
 const previousButton=$('atlas-previous'),nextButton=$('atlas-next');
 if(previousButton){previousButton.textContent=previous?'‹ '+String(previous.title||'Предыдущий урок'):'‹ Предыдущий урок';previousButton.title=previous?.title||''}
 if(nextButton){nextButton.textContent=next?String(next.title||'Следующий урок')+' ›':'Следующий урок ›';nextButton.title=next?.title||''}
 disabled('atlas-play',busy||!media||!hasClip);
 disabled('atlas-play-source',busy||!media);
 renderLocalTimeline(clip,pieces,duration,busy,!!media);
 const player=$('player');
 updateAtlasPlayhead({time:player?.currentTime??pieces[0]?.start??0,duration,
  playing:!!player&&!player.paused});
}

/** Fast playback update: keep focus and editable timeline nodes in place. */
export function updateAtlasPlayhead({time=0,duration=currentView.duration,playing=false}={}){
 time=clamp(number(time),0,Math.max(0,number(duration)));
 text('atlas-local-current',stamp(time));
 const track=$('atlas-local-track');
 if(track){
  const from=number(track.dataset.start),to=number(track.dataset.end);
  const playhead=track.querySelector('.atlas-local-playhead');
  if(playhead){
   playhead.hidden=!currentView.hasClip||!(to>from)||time<from||time>to;
   playhead.style.left=(100*clamp((time-from)/Math.max(.001,to-from),0,1))+'%';
  }
 }
 const play=$('atlas-play');
 if(play){
  play.textContent=playing?'❚❚':'▶';
  play.setAttribute('aria-label',playing?'Остановить воспроизведение':'Воспроизвести микроурок');
  play.setAttribute('aria-pressed',String(!!playing));
 }
 const inside=currentView.pieces.some(piece=>time>=piece.start&&time<piece.end);
 text('atlas-original-state',!currentView.hasMedia?
  'Привяжите исходное видео, чтобы включить воспроизведение.':
  !currentView.hasClip?'Выберите микроурок для сравнения.':
  inside?'Этот момент входит в микроурок. Исходное изображение и звук сохранены.':
  'Вне микроурока — этот момент не войдёт в монтаж.');
 const state=$('atlas-original-state');if(state)state.dataset.inClip=String(inside);
}
