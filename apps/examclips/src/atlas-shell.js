/** The selected Atlas interface, mounted around the existing media controls.
 * The engine remains the sole owner of projects, video, processing and exports.
 */
const $=id=>document.getElementById(id);
const element=(tag,cls,html='')=>{const node=document.createElement(tag);node.className=cls;node.innerHTML=html;return node};

export function mountAtlasShell(root,{getState,onLibrary,onTab,onStep,onRangeSelect,onRangeFind,onRangeCreate,onRangeClear,onSeek,onBoundary,onPrevious,onNext,onPlay,onAccept}={}){
 root.classList.add('atlas-app');
 const shell=root.querySelector('.shell'),workspace=root.querySelector('.workspace'),sidebar=root.querySelector('.sidebar');
 const top=root.querySelector('.top'),nav=root.querySelector('.top-navigation'),back=$('back-to-library'),privacy=root.querySelector('.privacy');
 const brand=element('button','atlas-brand','<span class="atlas-brand-icon">E</span><span class="atlas-brand-name">Exam<span>Clips</span></span><small>LECTURE<br>TO SHORTS</small>');
 brand.type='button';brand.setAttribute('aria-label','ExamClips — мои лекции');brand.onclick=onLibrary;
 const breadcrumb=element('div','atlas-breadcrumb','<span id="atlas-crumb-title">Мои лекции</span>');
 breadcrumb.prepend(back);
 privacy.textContent='● Всё хранится на устройстве';
 const theme=element('button','atlas-theme','☀');theme.id='atlas-theme';theme.type='button';
 theme.setAttribute('aria-label','Включить светлую тему');
 const setTheme=value=>{
  document.documentElement.dataset.uiTheme=value;
  theme.textContent=value==='light'?'☾':'☀';
  theme.setAttribute('aria-label',value==='light'?'Включить тёмную тему':'Включить светлую тему');
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content',value==='light'?'#f5f4f8':'#101015');
 };
 let savedTheme='dark';try{savedTheme=localStorage.getItem('examclips-ui-theme')||'dark'}catch{}
 setTheme(savedTheme==='light'?'light':'dark');
 theme.onclick=()=>{const value=document.documentElement.dataset.uiTheme==='light'?'dark':'light';setTheme(value);try{localStorage.setItem('examclips-ui-theme',value)}catch{}};
 top.replaceChildren(brand,breadcrumb,privacy,theme);
 const toolbar=element('div','atlas-toolbar');toolbar.append(nav);workspace.prepend(toolbar);
 const labels={timeline:'Оригинал и таймлайн',clip:'Микроуроки',captions:'Расшифровка',quiz:'Тесты',export:'Экспорт'};
 for(const button of nav.querySelectorAll('[data-editor-tab]'))button.textContent=labels[button.dataset.editorTab];
 nav.prepend(nav.querySelector('[data-editor-tab="clip"]'));

 const library=element('section','atlas-page','<div class="atlas-library-hero"><div class="atlas-library-copy"><span class="atlas-tag">Библиотека</span><h1>Лекции → <span>законченные микроуроки</span></h1></div><button id="atlas-new-lecture" class="atlas-new-card" type="button">Новая<br>лекция <span>+</span></button></div><div class="atlas-library-options"><p>Все содержательные объяснения. В одном месте.</p><button id="atlas-import-project" type="button">Открыть проект JSON</button></div>');
 library.id='atlas-library';library.append($('library-section'));shell.prepend(library);
 $('atlas-import-project').onclick=()=>$('load-project').click();
 const wizard=element('section','atlas-page','<div class="atlas-wizard-heading"><span class="atlas-tag">Новая лекция</span><h1>Подготовим микроуроки</h1><p>Три шага — затем анализ на вашем устройстве.</p></div><ol class="atlas-stepper" aria-label="Шаги подготовки"><li data-wizard-step="1"><b>1</b> Видео</li><li data-wizard-step="2"><b>2</b> Настройки</li><li data-wizard-step="3"><b>3</b> Подтверждение</li></ol><section id="wizard-step-1" class="atlas-step"><h2>Выберите исходную лекцию</h2><div id="wizard-preview" hidden></div></section><section id="wizard-step-2" class="atlas-step" hidden><h2>Речь и параметры анализа</h2><p>Ищем все законченные темы. Количество роликов определяет содержание лекции.</p><p id="wizard-srt-status" role="status"></p></section><section id="wizard-step-3" class="atlas-step" hidden><h2>Всё готово к обработке</h2><div id="wizard-summary"></div></section><div class="atlas-wizard-actions"><button id="wizard-back" type="button">← В библиотеку</button><button id="wizard-next" class="primary" type="button" disabled>Далее →</button></div>');
 wizard.id='atlas-wizard';wizard.hidden=true;library.after(wizard);
 const sourceStep=$('wizard-step-1'),settingsStep=$('wizard-step-2'),confirmStep=$('wizard-step-3');
 sourceStep.append($('drop'),$('file-note'),$('initial-duration'));
 const config=sidebar.querySelector('.config-group');
 const languageDetails=config.querySelector('details');
 if(languageDetails){const body=languageDetails.querySelector('.detail-body');languageDetails.replaceWith(body)}
 settingsStep.append(config);
 config.querySelector('.heading').hidden=true;
 $('import-srt').textContent='Выбрать готовые субтитры SRT';
 confirmStep.append(root.querySelector('.workflow-config-actions'));
 $('workflow-srt').textContent='Выбрать или заменить SRT';
 const analysis=element('section','atlas-analysis-panel','<h3>Анализ лекции</h3><p>Повторное распознавание использует сохранённые окна Whisper. Поиск тем использует текущую расшифровку.</p><button type="button" id="atlas-analysis-settings">Настройки распознавания</button><button type="button" id="atlas-reimport-srt">Импортировать другой SRT</button>');
 analysis.id='atlas-analysis-panel';
 analysis.append($('transcribe'),$('forget-asr'),sidebar.querySelector('.topic-settings'));
 $('pane-captions').append(analysis);
 $('atlas-reimport-srt').onclick=()=>$('import-srt').click();
 const processing=$('processing-panel');shell.insertBefore(processing,workspace);
 const missing=element('aside','atlas-source-missing','<div><strong>Проект открыт без оригинального видео</strong><p>Разметка и расшифровка сохранены. Привяжите исходник для воспроизведения и экспорта.</p></div><button id="atlas-attach-source" type="button">Привязать оригинал</button>');
 missing.id='atlas-source-missing';missing.hidden=true;toolbar.after(missing);
 $('atlas-attach-source').onclick=()=>$('video-file').click();
 const statusbar=element('div','atlas-statusbar');
 statusbar.append(root.querySelector('.progress-row'),$('autosave-state'),$('remember-video'));
 shell.after(statusbar);
 const overview=$('microtopic-overview');
 const hero=element('section','atlas-lecture-hero','<div><span class="atlas-tag">Микроуроки из вашей лекции</span><h1 id="atlas-lecture-title">Лекция</h1></div><div class="atlas-stats"><div><strong id="atlas-stat-clips">0</strong><span>микроуроков</span></div><div><strong id="atlas-stat-coverage">0%</strong><span>времени в роликах</span></div><div><strong id="atlas-stat-ready">0/0</strong><span>проверено</span></div></div>');
 hero.id='atlas-lecture-heading';overview.prepend(hero);
 const coverage=element('section','atlas-coverage','<div class="atlas-coverage-heading"><strong>Карта покрытия</strong><span><i class="atlas-dot kept"></i>В микротемах</span><span><i class="atlas-dot gap"></i>Не включено</span><span><i class="atlas-dot candidate"></i>Кандидаты</span><button id="atlas-select-range" type="button">Выбрать участок</button></div><div id="atlas-coverage-track" role="slider" tabindex="0" aria-label="Диапазон исходной лекции для поиска микротем" aria-valuemin="0" aria-valuemax="0"><div id="atlas-range-selection" hidden></div></div><div id="atlas-coverage-ruler" class="atlas-coverage-ruler"></div><div id="atlas-range-actions" hidden><label>От<input id="atlas-range-start" type="text" inputmode="decimal" aria-label="Начало выбранного участка"></label><label>До<input id="atlas-range-end" type="text" inputmode="decimal" aria-label="Конец выбранного участка"></label><button id="atlas-range-find" class="primary" type="button">Найти темы здесь ›</button><button id="atlas-range-create" type="button">Сделать клип как есть</button><button id="atlas-range-clear" type="button" aria-label="Снять выделение">✕</button><p>Поиск по сохранённой расшифровке. Новые кандидаты появятся отдельно; существующий монтаж сохранится.</p></div><p id="atlas-coverage-note" class="hint">Выделите участок мышью или задайте время, чтобы найти пропущенное. Процент времени не оценивает полноту учебных тем.</p>');
 coverage.id='atlas-coverage';hero.after(coverage);
 $('atlas-range-find').onclick=onRangeFind;$('atlas-range-create').onclick=onRangeCreate;$('atlas-range-clear').onclick=onRangeClear;
 $('atlas-select-range').onclick=()=>{const state=getState();onRangeSelect?.(0,Math.min(state.duration,60))};
 const rangeTrack=$('atlas-coverage-track');let dragStart=null;
 const at=(event)=>{const rect=rangeTrack.getBoundingClientRect();return Math.max(0,Math.min(getState().duration,(event.clientX-rect.left)/Math.max(1,rect.width)*getState().duration))};
 rangeTrack.addEventListener('pointerdown',event=>{if(getState().busy||!getState().duration)return;event.preventDefault();dragStart=at(event);rangeTrack.setPointerCapture(event.pointerId);onRangeSelect?.(dragStart,dragStart)});
 rangeTrack.addEventListener('pointermove',event=>{if(dragStart===null)return;onRangeSelect?.(Math.min(dragStart,at(event)),Math.max(dragStart,at(event)))});
 rangeTrack.addEventListener('pointerup',event=>{if(dragStart===null)return;const end=at(event);if(Math.abs(end-dragStart)<1)onRangeSelect?.(Math.max(0,end-15),Math.min(getState().duration,end+45));dragStart=null});
 rangeTrack.addEventListener('pointercancel',()=>{dragStart=null});
 rangeTrack.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();$('atlas-select-range').click()}};
 for(const id of ['atlas-range-start','atlas-range-end'])$(id).onchange=()=>onRangeSelect?.($('atlas-range-start').value,$('atlas-range-end').value);

 const detail=$('microtopic-detail');
 const heading=element('div','atlas-detail-head','<div class="atlas-detail-title"><span class="atlas-tag" id="atlas-detail-meta"></span></div><div class="atlas-detail-actions"><span id="atlas-detail-status"></span><button id="atlas-accept-current" type="button" class="primary" hidden>Принять в серию ›</button><button id="atlas-export-clip" type="button">Экспорт MP4 ↓</button></div>');
 const comparison=element('section','atlas-comparison');comparison.append(heading);$('microtopic-back').after(comparison);
 const title=$('clip-title');const titleLabel=title.closest('label');heading.querySelector('.atlas-detail-title').append(title);titleLabel.remove();title.setAttribute('aria-label','Заголовок микроурока');
 heading.querySelector('.atlas-detail-actions').prepend($('approve-topic'));
 $('atlas-export-clip').onclick=()=>$('export').click();$('atlas-accept-current').onclick=onAccept;
 const mediaRow=element('div','atlas-detail-media','<div class="atlas-original-panel"><div class="atlas-monitor-label">Было в лекции</div><div id="atlas-original-slot"></div><p id="atlas-original-state" class="hint"></p></div>');
 const portrait=detail.querySelector('.catalog-preview-panel');
 portrait.querySelector('b').textContent='Стало · 9:16';portrait.querySelector('.hint').textContent='Живой предпросмотр с исходным звуком';
 mediaRow.append(portrait);comparison.append(mediaRow);
 const localTimeline=element('section','atlas-local-timeline','<div class="atlas-local-toolbar"><button id="atlas-play" type="button" aria-label="Воспроизвести микроурок">▶</button><span id="atlas-local-current">00:00</span><button id="atlas-play-source" type="button">Смотреть оригинал</button><span class="hint">Тяните края, чтобы изменить границы · ±1 мин контекста</span></div><div id="atlas-local-track" role="group" aria-label="Монтаж и контекст выбранного микроурока"><div class="atlas-local-playhead"></div></div><div id="atlas-local-ruler" class="atlas-coverage-ruler"></div><div id="atlas-boundaries" class="two"></div>');
 localTimeline.id='atlas-local-timeline';
 const firstLabel=$('clip-start').closest('label'),lastLabel=$('clip-end').closest('label');$('atlas-boundaries')?.append(firstLabel,lastLabel);
 // The section is not connected until append; query locally for its slots.
 localTimeline.querySelector('#atlas-boundaries').append(firstLabel,lastLabel);
 comparison.append(localTimeline);
 $('atlas-play').onclick=onPlay;
 $('atlas-play-source').onclick=()=>onSeek?.($('player').currentTime||getState().clip?.start||0,true);
 const localTrack=$('atlas-local-track');
 localTrack.onpointerdown=event=>{
  if(event.target.closest('.atlas-local-handle')||getState().busy)return;
  const rect=localTrack.getBoundingClientRect(),start=Number(localTrack.dataset.start)||0,end=Number(localTrack.dataset.end)||getState().duration;
  onSeek?.(Math.max(start,Math.min(end,start+(event.clientX-rect.left)/Math.max(1,rect.width)*(end-start))));
 };
 localTrack.addEventListener('pointerdown',event=>{
  const handle=event.target.closest('.atlas-local-handle');if(!handle||getState().busy)return;
  event.preventDefault();event.stopPropagation();
  const rect=localTrack.getBoundingClientRect(),start=Number(localTrack.dataset.start),end=Number(localTrack.dataset.end);
  const piece=Number(handle.dataset.piece),edge=handle.dataset.edge;
  const release=up=>{document.removeEventListener('pointerup',release);onBoundary?.(piece,edge,Math.max(start,Math.min(end,start+(up.clientX-rect.left)/Math.max(1,rect.width)*(end-start))))};
  document.addEventListener('pointerup',release,{once:true});
 });
 localTrack.addEventListener('keydown',event=>{
  const handle=event.target.closest('.atlas-local-handle');if(!handle||!['ArrowLeft','ArrowRight'].includes(event.key))return;
  event.preventDefault();onBoundary?.(Number(handle.dataset.piece),handle.dataset.edge,Number(handle.dataset.time)+(event.key==='ArrowLeft'?-1:1)*(event.shiftKey?10:.5));
 });
 const editToggle=element('button','atlas-edit-toggle','Кадр и монтаж <span>↗</span>');editToggle.type='button';editToggle.id='atlas-edit-toggle';editToggle.setAttribute('aria-expanded','false');
 const editPanel=element('section','atlas-edit-panel');editPanel.id='atlas-edit-panel';editPanel.hidden=true;
 editPanel.append($('editor'),detail.querySelector('.story-pieces-editor'),detail.querySelector('.screenplay-review'));
 for(const details of editPanel.querySelectorAll('details.detail-settings')){const contents=details.querySelector('.detail-body');if(contents)details.replaceWith(contents)}
 detail.append(editToggle,editPanel);
 editToggle.onclick=()=>{editPanel.hidden=!editPanel.hidden;editToggle.setAttribute('aria-expanded',String(!editPanel.hidden))};
 const detailNav=element('nav','atlas-detail-nav','<button id="atlas-previous" type="button">‹ Предыдущий урок</button><span id="atlas-detail-index"></span><button id="atlas-next" type="button">Следующий урок ›</button>');
 detail.append(detailNav);$('atlas-previous').onclick=onPrevious;$('atlas-next').onclick=onNext;
 document.addEventListener('keydown',event=>{
  if(getState().phase!=='results'||!getState().detailOpen||getState().busy)return;
  if(event.target.closest('input,textarea,select,button,[contenteditable="true"]')||event.ctrlKey||event.altKey||event.metaKey)return;
  if(event.key==='ArrowLeft'){event.preventDefault();onPrevious?.()}
  if(event.key==='ArrowRight'){event.preventDefault();onNext?.()}
  if(event.key===' '){event.preventDefault();onPlay?.()}
  if(event.key==='Escape')$('microtopic-back').click();
 });

 let step=1;
 function summary(){
  const fields=[['Лекция',getState().title],['Язык',$('language').selectedOptions[0].textContent],['Модель',$('asr-model').selectedOptions[0].textContent],['Анализ',$('asr-limit').selectedOptions[0].textContent],['Источник речи',getState().pendingSrt?'Готовые субтитры SRT':'Распознавание Whisper на устройстве']];
  const list=element('dl','atlas-summary-list');
  for(const [label,value] of fields){const row=element('div','');const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;row.append(dt,dd);list.append(row)}
  $('wizard-summary').replaceChildren(list);
 }
 function setStep(next){
  step=Math.max(1,Math.min(3,next));
  for(let n=1;n<=3;n++)$('wizard-step-'+n).hidden=n!==step;
  for(const item of wizard.querySelectorAll('[data-wizard-step]')){item.classList.toggle('current',Number(item.dataset.wizardStep)===step);item.classList.toggle('done',Number(item.dataset.wizardStep)<step)}
  $('wizard-back').textContent=step===1?'← В библиотеку':'← Назад';$('wizard-next').hidden=step===3;
  summary();onStep?.(step);
 }
 function showWizard(next=1){library.hidden=true;wizard.hidden=false;setStep(next);placePlayer();}
 function showLibrary(){library.hidden=false;wizard.hidden=true;step=1;placePlayer()}
 $('atlas-new-lecture').onclick=()=>showWizard(1);
 $('wizard-next').onclick=()=>{if(!getState().media)return;setStep(step+1)};
 $('wizard-back').onclick=()=>step===1?onLibrary?.():setStep(step-1);
 $('atlas-analysis-settings').onclick=()=>showWizard(2);
 function placePlayer(){
  const state=getState();const target=state.phase==='results'&&state.detailOpen&&state.activeTab==='clip'?$('atlas-original-slot'):
   !wizard.hidden?$('wizard-preview'):root.querySelector('.source-monitor-content');
  const player=$('player');if(target&&player.parentElement!==target){const playing=!player.paused;target.append(player);if(playing)player.play().catch(()=>{})}
  $('wizard-preview').hidden=!state.media;
 }
 function update(){
  const state=getState();
  if(state.phase==='results'||state.phase==='processing'){library.hidden=true;wizard.hidden=true}
  else if(state.media&&wizard.hidden)showWizard(1);
  $('wizard-next').disabled=!state.media||state.busy;
  $('atlas-new-lecture').disabled=state.busy;$('atlas-import-project').disabled=state.busy;
  missing.hidden=!state.hasProject||!!state.media;
  $('atlas-crumb-title').textContent=state.phase==='results'?state.title:'Мои лекции';
  back.hidden=!state.hasProject&&state.phase!=='processing';
  $('atlas-lecture-title').textContent=state.title||'Лекция';
  $('wizard-srt-status').textContent=state.pendingSrt?'✓ SRT выбран. Он будет использован после подтверждения.':'';
  $('workflow-start').textContent=state.pendingSrt?'Найти микроуроки по SRT →':'Обработать лекцию →';
  if(!wizard.hidden&&step===3)summary();
  placePlayer();
 }
 return {update,showLibrary,showWizard,setStep,placePlayer,get step(){return step}};
}
