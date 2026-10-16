import './styles.css';
import {quizForClip,gradeQuiz,toQuizJson} from './quiz.js';
import {openMedia} from './media.js';
import {transcribe} from './asr.js';
import {buildClips,parseSrt,toSrt,validRange,timecode,textAt} from './segments.js';
import {paintFrame,WIDTH,HEIGHT} from './composition.js';
import {exportClip} from './render.js';
import {analyzeScene} from './scene-analysis.js';
import {sampleSlideCuts} from './slide-cuts.js';
import {makeStoryboard} from './scene-model.js';
import {buildMicrotopics,coverageReport} from './microtopics.js';
import {captionCueAt} from './editorial-motion.js';
import {captionSequenceAt} from './caption-flow.js';
import {timelinePieces,timelineStats,timelineTimeAtFraction,amendClipBoundary} from './source-timeline.js';
import {buildReviewPayload} from './completion-review.js';
import {checkpointKey,loadCheckpoint,saveCheckpoint,deleteCheckpoint} from './asr-checkpoint.js';
const isLocalDesktop=['localhost','127.0.0.1','::1'].includes(window.location.hostname);
let localReviewAvailable=false;
const root=document.querySelector('#app');
root.dataset.phase='upload';
root.innerHTML=`
<header class="top">
 <div class="brand"><span class="brand-icon">▶</span> ExamClips <span class="pill">BETA</span></div>
 <nav class="top-navigation" aria-label="Разделы">
  <button data-scroll="overview" class="active" type="button">Обзор</button>
  <button data-scroll="editor" type="button">Микротемы</button>
  <button data-scroll="quiz-panel" type="button">Тесты</button>
 </nav>
 <div class="privacy">● Видео остаётся на устройстве</div>
</header>
<main class="shell">
  <aside class="sidebar">
    <div class="heading">Новая обработка <span class="muted">Приватно</span></div>
    <label class="drop" id="drop"><span class="drop-icon">⬆</span><b>Выберите видео</b><small>MP4, MOV, WebM · до 180 мин / 2 ГБ</small><input type="file" id="video-file" accept="video/mp4,video/quicktime,video/webm,video/*" hidden></label>
    <div class="file-note" id="file-note">Файл пока не выбран. Ничего не загружается на сервер.</div>
 <div class="onboarding">1. Выбери запись лекции. 2. Распознай речь или импортируй SRT. 3. Проверь фрагменты и получи вертикальные видео.</div>
    <div class="settings config-group">
      <div class="heading">1. Расшифровка</div>
      <details class="detail-settings"><summary>Язык и параметры Whisper</summary><div class="detail-body">
      <label>Распознавание речи<select id="language"><option value="auto">Авто (RU / EN)</option><option value="ru">Русский</option><option value="en">English</option></select></label>
      <label>Размер локальной модели<select id="asr-model">
        <option value="tiny">Whisper Tiny — быстрый режим</option>
        <option value="base">Whisper Base — качественнее, требует больше ресурсов</option>
      </select></label>
      <label>Объём для распознавания<select id="asr-limit"><option value="all" selected>Вся лекция — полный анализ микротем</option><option value="300">Первые 5 минут — быстрая проба</option><option value="900">Первые 15 минут — проба</option></select></label>
      </div></details>
      <button class="primary" id="transcribe" disabled>✦ Распознать лекцию локально</button>
      <button id="forget-asr" disabled>Удалить сохранённую расшифровку из кэша</button>
      <button id="import-srt" disabled>Импорт SRT (без AI)</button>
      <input type="file" accept=".srt,text/plain" id="srt-file" hidden>
      <p class="hint">При первом запуске выбранной Whisper скачиваются веса модели (Tiny или Base). Полная обработка часовой лекции может быть долгой на слабом ПК; для проверки выберите первые 5 минут. Видеоданные не загружаются в облако.</p>
    </div>
    <div class="settings topic-settings">
  <div class="heading">2. Найти микротемы</div>
  <label>Длительность<select id="topic-preset">
    <option value="full">Полная мысль · обычно 1–3 мин, максимум 5 мин</option>
    <option value="compact">Короткие объяснения · обычно 1–2 мин, максимум 3 мин</option>
  </select></label>
  <button id="scan-chapters" disabled>◫ Найти смены слайдов локально</button>
  <button id="suggest-topics" disabled>✧ Предложить законченные микротемы</button>
  <p class="hint" id="topic-coverage">Для смысловой нарезки нужна расшифровка речи. Рекомендации по границам предварительные: проверьте начало и вывод каждой микротемы.</p>
</div>
<div class="section-title clip-heading">3. Готовые фрагменты <span id="clip-count">0</span></div>
    <div id="clips" class="clips"><p class="empty">После загрузки предложим фрагменты. Начальную и конечную границу можно изменять.</p></div>
  </aside>
  <section class="workspace" id="overview">
    <div class="workspace-top"><div><div class="eyebrow">ОБРАБОТКА ЛЕКЦИЙ · EXAMCLIPS</div><h1>Из лекции — в понятные короткие видео</h1><p class="lead">Текст, формулы и слайды остаются в кадре. Монтаж и расшифровка выполняются на устройстве.</p></div><span class="status" id="status">Ожидание видео</span></div>
    <div class="workflow-config">
      <div class="workflow-config-icon">✦</div>
      <h2>Лекция загружена. Как будем обрабатывать?</h2>
      <p>Выберите язык и режим в левой панели. Расшифровка, определение микротем и подготовка монтажа запускаются последовательно.</p>
      <div class="workflow-config-actions">
        <button class="primary" id="workflow-start" disabled>Начать анализ лекции →</button>
        <button id="workflow-srt" disabled>У меня уже есть SRT</button>
      </div>
      <p class="hint">Видео останется на этом устройстве. Модели Whisper могут скачиваться при первом запуске.</p>
    </div>
    <section id="processing-panel" class="processing-panel" aria-label="Текущий ход анализа" hidden>
      <div class="processing-header"><div><span class="eyebrow" id="processing-step-label">ЭТАП 1 ИЗ 4</span>
        <h2 id="processing-title">Обработка видео</h2></div><strong id="processing-percent">Подготовка</strong></div>
      <div class="processing-meter" role="progressbar" aria-label="Прогресс текущей операции" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span id="processing-meter-fill"></span></div>
      <div class="processing-stages">
        <div data-process="prepare" class="current"><b>01</b><span>Подготовка</span></div>
        <div data-process="asr"><b>02</b><span>Распознавание</span></div>
        <div data-process="topics"><b>03</b><span>Выбор тем</span></div>
        <div data-process="composition"><b>04</b><span>Монтаж</span></div>
      </div>
      <p id="processing-detail">Чтение локального файла…</p>
      <button id="processing-cancel" type="button">Остановить операцию</button>
    </section>
    <div class="journey" aria-label="Этапы обработки">
      <div class="journey-step" id="journey-upload"><div class="journey-number">1</div><div><b>Лекция</b><small id="journey-upload-state">Выберите файл</small></div></div>
      <div class="journey-step" id="journey-transcript"><div class="journey-number">2</div><div><b>Транскрипция</b><small id="journey-transcript-state">Whisper / SRT</small></div></div>
      <div class="journey-step" id="journey-topics"><div class="journey-number">3</div><div><b>Микротемы</b><small id="journey-topics-state">1–5 минут</small></div></div>
      <div class="journey-step" id="journey-output"><div class="journey-number">4</div><div><b>Ролики + тесты</b><small>Экспорт на устройство</small></div></div>
    </div>
    <div class="kpis" aria-label="Локальная статистика проекта">
      <div class="kpi"><strong id="kpi-topics">0</strong><span>Микротем найдено</span></div>
      <div class="kpi"><strong id="kpi-duration">0 мин</strong><span>Длительность фрагментов</span></div>
      <div class="kpi"><strong id="kpi-approved">0</strong><span>Проверено вручную</span></div>
    </div>
    <div class="editor" id="editor">
      <div class="stage"><canvas id="preview" width="${WIDTH}" height="${HEIGHT}"></canvas><video id="player" controls playsinline preload="metadata"></video><p class="stage-note">Предпросмотр · вертикальный формат 9:16</p></div>
      <div class="controls">
        <div class="panel-title"><b id="selected-title">Настройки микротемы</b><span class="muted" id="selected-time"></span></div>
  <div id="topic-review" class="topic-review">Проверьте, что ролик понятен без просмотра предыдущих частей лекции.</div>
  <button id="approve-topic" disabled>✓ Проверил вступление, объяснение и вывод</button>
  <div class="settings" style="margin:0;padding-bottom:8px">
    <button id="verify-topic" disabled>✧ Проверить завершённость через локальную LLM</button>
    <p class="hint" id="review-state">Необязательно: проверка в установленной Ollama на этом компьютере, без отправки речи и видео в интернет. Она предлагает исправления, но не меняет границы автоматически.</p>
    <button id="apply-review" disabled>Применить предложенные границы</button>
  </div>
        <label>Заголовок<input id="clip-title" disabled maxlength="90"></label>
        <div class="two"><label>Начало, сек<input type="number" id="clip-start" min="0" step=".1" disabled></label><label>Конец, сек<input type="number" id="clip-end" min="0" step=".1" disabled></label></div>
        <details class="detail-settings"><summary>Расширенные настройки монтажа и OCR</summary><div class="detail-body">
        <label>Композиция<select id="layout" disabled><option value="hybrid">AI-композиция: объекты + вебка</option><option value="fit">Исходный слайд целиком</option><option value="focus">Акцент на выбранной области</option><option value="crop">Заполнить вертикальный кадр</option></select></label>
        <label>Движок распознавания слайдов<select id="ocr-engine">
<option value="auto">Авто — RapidOCR, если установлен; иначе Tesseract.js</option>
<option value="tesseract">Tesseract.js — полностью в браузере</option>
<option value="rapid">RapidOCR — PP-OCRv6 (EN) / PP-OCRv5 (RU)</option>
</select></label>
<button id="analyze-scene" disabled>✧ Распознать доску (локальный OCR)</button><p class="hint" id="scene-hint">AI-композиция использует оригинальные области слайда. OCR включается по кнопке, первый раз скачивает языковую модель.</p><label>Визуальный стиль<select id="style-theme" disabled>
<option value="warm">Warm Classroom — светлый</option>
<option value="midnight">Midnight Notes — тёмный</option>
</select></label>
<label>Расположение вебки<select id="speaker-preset" disabled>
<option value="auto">Авто: по движению / справа внизу</option>
<option value="right">Справа внизу</option><option value="left">Слева внизу</option>
<option value="top-right">Справа вверху</option><option value="top-left">Слева вверху</option>
<option value="none">Без вебки</option></select></label>
<label>Горизонтальный фокус <span id="focus-value">50%</span><input id="focus" type="range" min="0" max="100" value="50" disabled></label>
        <label>Качество экспорта<select id="output-quality">
<option value="standard">Быстро — 720×1280, 15 FPS</option>
<option value="high">Качественно — 1080×1920, 30 FPS</option>
</select></label>
</div></details>
<div class="buttons"><button id="play-clip" disabled>▶ Посмотреть</button><button class="primary" id="export" disabled>↓ Экспорт MP4</button></div>
<button id="export-all" disabled>↓ Экспортировать все микротемы в папку</button>
        <div class="buttons">
  <button id="extend-start" disabled>← Ещё 15 сек в начале</button>
  <button id="extend-end" disabled>Ещё 15 сек в конце →</button>
</div>
<div class="buttons">
  <button id="listen-context" disabled>▶ Прослушать с контекстом</button>
  <button id="add" disabled>+ Добавить клип</button>
</div>
<button id="remove" disabled>Удалить микротему</button>
        <div class="divider"></div>
        <div class="panel-title"><b>Транскрипт и субтитры</b><button class="plain" id="save-srt" disabled>Скачать SRT</button></div>
        <textarea id="transcript" rows="7" placeholder="Здесь появятся субтитры с таймкодами. Можно импортировать готовый SRT." disabled></textarea>
        <p class="hint">Автоматические таймкоды Whisper могут быть приблизительными; проверьте перед публикацией.</p>
        <div class="panel-title"><b>Проект</b><button class="plain" id="save-project" disabled>Сохранить JSON</button></div>
        <p class="hint">Проект хранит разметку, но не само видео: при повторном открытии понадобится выбрать исходный файл.</p>
        <button id="load-project">Открыть проект JSON</button><input id="project-file" type="file" accept=".json,application/json" hidden>
      </div>
    </div>
    <section class="timeline-section" id="timeline-section">
      <div class="timeline-heading">
        <div><div class="eyebrow">ИСТОЧНИК И МОНТАЖ</div>
          <h2>Таймлайн лекции</h2>
          <p class="hint">Синие участки попадут в ролики, серые будут пропущены. Выбирайте фрагменты и перетаскивайте края, как в видеоредакторе.</p></div>
        <div class="timeline-actions">
          <button id="timeline-regenerate" disabled>↻ Перенарезать по речи</button>
          <button id="timeline-recompose" disabled>✧ Пересобрать выбранный кадр</button>
        </div>
      </div>
      <div class="timeline-legend"><span><i class="legend-kept"></i>В ролике</span><span><i class="legend-skipped"></i>Пропущено</span><span id="timeline-coverage">0% лекции выбрано</span></div>
      <div class="timeline-ruler" id="timeline-ruler"></div>
      <div class="timeline-source" id="timeline-source" aria-label="Оригинальная лекция. Нажмите, чтобы перейти ко времени."><div id="timeline-playhead"></div></div>
      <div id="timeline-track" class="timeline-track" aria-label="Выбранные фрагменты и пропуски"></div>
      <div class="timeline-foot">
        <span id="timeline-current">00:00:00 / 00:00:00</span>
        <button id="timeline-add" disabled>+ Создать клип в этой точке</button>
      </div>
    </section>
    <section class="quiz-panel" id="quiz-panel">
      <div class="quiz-header">
        <div><h2>Мини-тест по материалу</h2>
          <p class="quiz-intro">Проверка ключевых терминов из реальной речи преподавателя. Ответы остаются в браузере.</p></div>
        <div class="quiz-actions"><button id="quiz-generate" disabled>Создать тест</button><button id="quiz-download" disabled>↓ JSON теста</button></div>
      </div>
      <div id="quiz-content" aria-live="polite"><p class="empty">Сначала распознайте лекцию и выберите микротему.</p></div>
      <button id="quiz-grade" disabled>Проверить ответы</button>
      <div id="quiz-result" class="quiz-result" hidden></div>
      <p class="hint" style="margin-top:12px">Это тест на воспроизведение терминов из транскрипта, а не автоматически проверенная оценка понимания темы.</p>
    </section>
    <div class="progress-row"><div id="progress" aria-live="polite">Готов к загрузке лекции</div><button id="cancel" disabled>Остановить</button></div>
  </section>
</main>
<footer>ExamClips · Локальная обработка · Без загрузки исходных видео · Проверяйте формулы, субтитры и границы тем перед публикацией</footer>`;
const $=id=>document.getElementById(id);

const generatedQuizzes=new Map(),quizSelections=new Map();
function quizKey(c){return c?[c.id,c.start,c.end,c.title].join('|'):''}
function updateDashboard(){
 const ready=clips.filter(c=>c.id!=='draft-1'&&c.end>c.start);
 const checked=ready.filter(c=>c.status==='approved');
 $('kpi-topics').textContent=String(ready.length);
 $('kpi-approved').textContent=String(checked.length);
 $('kpi-duration').textContent=Math.round(ready.reduce((sum,c)=>sum+c.end-c.start,0)/60)+' мин';
 const stages=[
   ['journey-upload',!!media,'journey-upload-state',media?'Видео выбрано':'Выберите файл'],
   ['journey-transcript',chunks.length>0,'journey-transcript-state',chunks.length+' реплик'],
   ['journey-topics',ready.length>0,'journey-topics-state',ready.length+' предложено'],
   ['journey-output',checked.length>0,null,null]
 ];
 for(const [id,done,caption,text] of stages){
   $(id).classList.toggle('done',done);
   if(caption&&text!==null)$(caption).textContent=text;
 }
}
function renderQuiz(){
 const mount=$('quiz-content');mount.replaceChildren();
 const clip=current(),key=quizKey(clip);
 const questions=generatedQuizzes.get(key)||[];
 $('quiz-generate').disabled=!media||!chunks.length||!clip||clip.id==='draft-1'||busy;
 $('quiz-download').disabled=!questions.length||busy;
 $('quiz-grade').disabled=!questions.length||busy;
 $('quiz-result').hidden=true;
 if(!questions.length){
   const p=document.createElement('p');p.className='empty';
   p.textContent=chunks.length?'Выберите микротему и нажмите «Создать тест». Вопросы формируются только по тексту выбранной темы.':'После расшифровки здесь можно создать проверку терминов из лекции.';
   mount.append(p);return;
 }
 const answers=quizSelections.get(key)||[];
 questions.forEach((q,i)=>{
   const section=document.createElement('section');section.className='quiz-question';
   const heading=document.createElement('b');heading.textContent=(i+1)+'. '+q.prompt;
   const quote=document.createElement('p');quote.className='quiz-quote';quote.textContent='«'+q.quote+'»';
   const options=document.createElement('div');options.className='quiz-options';
   q.options.forEach((option,j)=>{
      const label=document.createElement('label'),radio=document.createElement('input');
      radio.type='radio';radio.name='q-'+i;radio.value=String(j);radio.checked=answers[i]===j;
      radio.onchange=()=>{const selections=quizSelections.get(key)||[];selections[i]=j;quizSelections.set(key,selections)};
      const text=document.createElement('span');text.textContent=option;label.append(radio,text);options.append(label);
   });
   section.append(heading,quote,options);mount.append(section);
 });
}
async function probeLocalReview(){
 if(!isLocalDesktop)return;
 try{
   const response=await fetch('/api/local-review-capabilities',{cache:'no-store',signal:AbortSignal.timeout(4000)});
   if(!response.ok||!String(response.headers.get('content-type')||'').includes('application/json'))return;
   const result=await response.json();
   localReviewAvailable=Boolean(result.available);
   if(!localReviewAvailable)$('review-state').textContent='Ollama не найдена на этом ПК; проверка качества тем остаётся ручной.';
   enable();
 }catch{/* Static or offline browser fallback without local Ollama */}
}
function initMvpEvents(){
 $('workflow-start').onclick=()=>$('transcribe').click();
 $('workflow-srt').onclick=()=>$('import-srt').click();
 $('processing-cancel').onclick=()=>abort?.abort();
 $('timeline-source').onclick=e=>{
   if(!media)return;
   const rect=e.currentTarget.getBoundingClientRect();
   $('player').currentTime=timelineTimeAtFraction((e.clientX-rect.left)/Math.max(1,rect.width),media.duration);
   updateTimelinePlayhead();
 };
 $('timeline-track').onclick=e=>{
   if(!media||busy||!e.target.classList.contains('skipped'))return;
   const rect=$('timeline-track').getBoundingClientRect();
   $('player').currentTime=timelineTimeAtFraction((e.clientX-rect.left)/Math.max(1,rect.width),media.duration);
   updateTimelinePlayhead();
   status('Выбран пропущенный участок. Можете создать клип из текущей точки.');
 };
 $('timeline-regenerate').onclick=()=>{
   if(!media||!chunks.length)return;
   if(!confirm('Повторно найти микротемы? Текущие ручные изменения границ и их подтверждения будут заменены.'))return;
   proposeTopics();status('Нарезка пересчитана. Проверьте новый список клипов.');
 };
 $('timeline-recompose').onclick=()=>{
   if(!media||!current()||busy)return;
   $('analyze-scene').click();
 };
 $('timeline-add').onclick=()=>{
   if(!media||busy)return;
   const start=Math.max(0,Math.min(media.duration-.6,$('player').currentTime||0));
   const end=Math.min(media.duration,start+60);
   clips.push({id:'manual-'+Date.now(),start,end,title:'Добавленный фрагмент — нужна проверка',
      layout:'hybrid',focusX:50,status:'needs-review',
      reviewReasons:['Фрагмент добавлен из исходной лекции; проверьте смысл и границы']});
   selected=clips.length-1;setPhase('results');sync();
   status('Фрагмент добавлен из исходной лекции. Можно поменять его границы на дорожке.');
 };

 document.querySelectorAll('[data-scroll]').forEach(button=>{
   button.addEventListener('click',()=>{
     const anchor=document.getElementById(button.dataset.scroll);
     if(!anchor)return;
     anchor.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'start'});
     document.querySelectorAll('[data-scroll]').forEach(x=>x.classList.toggle('active',x===button));
   });
 });
 if(!isLocalDesktop){
   const opt=$('ocr-engine').querySelector('option[value="rapid"]');if(opt)opt.disabled=true;
   $('ocr-engine').value='tesseract';
 }
 $('quiz-generate').onclick=()=>{
   const clip=current();if(!clip)return;
   const key=quizKey(clip),questions=quizForClip(clip,chunks,{count:5});
   generatedQuizzes.set(key,questions);quizSelections.delete(key);
   renderQuiz();
   status(questions.length?'Создано '+questions.length+' вопросов по исходной речи. Проверьте формулировки.':'В выбранной микротеме пока недостаточно распознанных предложений для достоверного теста.');
 };
 $('quiz-grade').onclick=()=>{
   const key=quizKey(current()),questions=generatedQuizzes.get(key)||[],choices=quizSelections.get(key)||[];
   if(!questions.length)return;
   const outcome=gradeQuiz(questions,choices);
   $('quiz-result').hidden=false;
   $('quiz-result').textContent='Результат: '+outcome.correct+' из '+outcome.total+
       ' · '+outcome.percent+'%. Это оценка узнавания терминов, а не экзамен на понимание.';
 };
 $('quiz-download').onclick=()=>{
   const clip=current();if(!clip)return;
   const questions=generatedQuizzes.get(quizKey(clip))||[];if(!questions.length)return;
   download(new Blob([JSON.stringify(toQuizJson(clip,questions),null,2)],{type:'application/json;charset=utf-8'}),
     safeName(clip.title)+'.quiz.json');
 };
}

let media=null,sourceFile=null,originalUrl=null,clips=[],chunks=[],sceneCuts=[],selected=0,busy=false,abort=null,previewRaf=0,projectToRestore=null;
function setPhase(value){
 if(!['upload','configure','processing','results'].includes(value))return;
 root.dataset.phase=value;
 $('processing-panel').hidden=value!=='processing';
}
function showOperation(stage,percent,message,{standalone=false}={}){
 const stages=['prepare','asr','topics','composition'];
 const i=Math.max(0,stages.indexOf(stage));
 $('processing-panel').hidden=false;
 $('processing-title').textContent=['Подготовка','Распознаём речь','Формируем микротемы','Создаём видео'][i];
 $('processing-step-label').textContent='ЭТАП '+(i+1)+' ИЗ 4';
 $('processing-detail').textContent=message;
 const bar=$('processing-panel').querySelector('.processing-meter');
 const pct=Number.isFinite(percent)?Math.round(Math.max(0,Math.min(100,percent))):null;
 $('processing-meter-fill').style.width=(pct??7)+'%';
 bar.classList.toggle('indeterminate',pct===null);
 if(pct===null)bar.removeAttribute('aria-valuenow');else bar.setAttribute('aria-valuenow',String(pct));
 $('processing-percent').textContent=pct===null?'Выполняется':pct+'% этапа';
 document.querySelectorAll('[data-process]').forEach((el,j)=>{
  el.classList.toggle('current',j===i);el.classList.toggle('done',j<i);
 });
 if(standalone&&root.dataset.phase!=='results')setPhase('processing');
}
async function buildPrivateFilmstrip(videoMedia){
 // Sampled thumbnails are created and retained only in this browser session.
 const holder=$('timeline-source');
 holder.querySelectorAll('.filmstrip-tile').forEach(x=>x.remove());
 const N=10;
 for(let i=0;i<N;i++){
   if(media!==videoMedia)return;
   const at=Math.max(0,Math.min(videoMedia.duration-.05,videoMedia.duration*(i+.5)/N));
   try{
     const sample=await videoMedia.videoSink.getSample(at);
     if(!sample)continue;
     const image=document.createElement('canvas');image.width=150;image.height=84;
     try{sample.draw(image.getContext('2d'),0,0,150,84)}finally{sample.close()}
     if(media!==videoMedia)return;
     const tile=document.createElement('div');tile.className='filmstrip-tile';
     tile.style.left=(i*100/N)+'%';tile.style.width=(100/N)+'%';
     tile.style.backgroundImage='url("'+image.toDataURL('image/jpeg',.55)+'")';
     tile.setAttribute('aria-hidden','true');holder.append(tile);
   }catch{ /* Some video codecs cannot seek efficiently; keep plain track. */ }
 }
}
function renderTimeline(){
 const track=$('timeline-track'),ruler=$('timeline-ruler');
 track.replaceChildren();ruler.replaceChildren();
 if(!media){$('timeline-current').textContent='00:00:00 / 00:00:00';return}
 const duration=media.duration,spans=timelinePieces(clips,duration),stat=timelineStats(clips,duration);
 $('timeline-coverage').textContent=stat.percent+'% лекции выбрано · '+stat.clips+' фрагментов';
 const tickCount=Math.max(2,Math.min(12,Math.floor(duration/60)||2));
 for(let i=0;i<=tickCount;i++){
   const tick=document.createElement('span');tick.className='timeline-tick';
   tick.style.left=(i/tickCount*100)+'%';
   tick.textContent=timecode(duration*i/tickCount).slice(duration>=3600?0:3,8);
   ruler.append(tick);
 }
 const active=current();
 for(const span of spans){
   const el=document.createElement('div');el.className='timeline-part '+span.kind;
   el.style.left=(span.start/duration*100)+'%';
   el.style.width=((span.end-span.start)/duration*100)+'%';
   if(span.kind==='clip'){
      el.classList.toggle('active',span.id===active?.id);
      const idx=clips.findIndex(c=>c.id===span.id);
      el.title=(span.title||'Микротема')+' · '+timecode(span.start)+' — '+timecode(span.end);
      el.setAttribute('role','button');el.tabIndex=0;
      el.setAttribute('aria-label','Перейти к '+(span.title||'микротеме'));
      const label=document.createElement('span');label.className='timeline-part-text';
      label.textContent=String(idx+1).padStart(2,'0')+' · '+(span.title||'Фрагмент');
      el.append(label);
      el.onclick=()=>{if(busy)return;selected=idx;sync();$('player').currentTime=span.start};
      el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();el.click()}};
      for(const edge of ['start','end']){
        const handle=document.createElement('button');handle.type='button';
        handle.className='timeline-handle '+edge;
        handle.title=edge==='start'?'Изменить начало':'Изменить конец';
        handle.setAttribute('aria-label',handle.title);
        handle.addEventListener('pointerdown',e=>{
          if(busy)return;
          e.preventDefault();e.stopPropagation();
          const initial=clips[idx];const rect=track.getBoundingClientRect();
          const move=event=>{
            const t=timelineTimeAtFraction((event.clientX-rect.left)/rect.width,duration);
            handle.dataset.preview=timecode(t);
            el.title='Новая граница: '+timecode(t);
          };
          const release=event=>{
            document.removeEventListener('pointermove',move);
            document.removeEventListener('pointerup',release);
            const t=timelineTimeAtFraction((event.clientX-rect.left)/rect.width,duration);
            try{clips[idx]=amendClipBoundary(initial,edge,t,duration);selected=idx;sync();
              status('Граница сохранена. Проверьте микротему и заново создайте композицию.')}
            catch(err){status('Не удалось изменить границу: '+err.message);renderTimeline()}
          };
          document.addEventListener('pointermove',move);document.addEventListener('pointerup',release,{once:true});
        });
        el.append(handle);
      }
   }else{el.title='Пропущено: '+timecode(span.start)+' — '+timecode(span.end)}
   track.append(el);
 }
 $('timeline-add').disabled=busy||!media;
 $('timeline-regenerate').disabled=busy||!chunks.length;
 $('timeline-recompose').disabled=busy||!current()||current()?.id==='draft-1';
 updateTimelinePlayhead();
}
function updateTimelinePlayhead(){
 if(!media)return;
 const now=$('player').currentTime||0;
 const percent=Math.max(0,Math.min(100,now/media.duration*100));
 $('timeline-playhead').style.left=percent+'%';
 $('timeline-current').textContent=timecode(now).slice(0,8)+' / '+timecode(media.duration).slice(0,8);
}
function status(msg){$('progress').textContent=msg;$('status').textContent=msg.slice(0,48);if(!$('processing-panel').hidden)$('processing-detail').textContent=msg}
function error(e){console.error(e);status('Ошибка: '+(e.message||String(e)))}
function enable(){
  const has=!!media,clip=!!clips.length;
  $('transcribe').disabled=!has||busy;$('import-srt').disabled=!has||busy;
  for(const id of ['timeline-regenerate','timeline-recompose','timeline-add'])if($(id))$(id).disabled=busy||!has||(id==='timeline-regenerate'&&!chunks.length);
  $('workflow-start').disabled=!has||busy;
  $('workflow-srt').disabled=!has||busy;
  $('scan-chapters').disabled=!has||busy;
  $('forget-asr').disabled=!has||busy;
  $('suggest-topics').disabled=!has||busy||!chunks.length;
  $('quiz-generate').disabled=!has||busy||!chunks.length||current()?.id==='draft-1';
  $('export-all').disabled=!has||busy||!chunks.length||clips.every(c=>c.id==='draft-1');
  $('verify-topic').disabled=!isLocalDesktop||!localReviewAvailable||!clip||busy||!chunks.length||current()?.id==='draft-1';
  $('apply-review').disabled=!clip||busy||!current()?.llmReview?.evidenceVerified||
    !((current()?.llmReview?.suggestedStartDelta||0)||(current()?.llmReview?.suggestedEndDelta||0));
  for(const id of ['clip-title','clip-start','clip-end','layout','focus','play-clip','export','remove','analyze-scene','speaker-preset','style-theme','extend-start','extend-end','listen-context','approve-topic'])$(id).disabled=!clip||busy;
  // Never accidentally export the arbitrary, untranscribed loading placeholder as a finished micro-lesson.
  $('export').disabled=!clip||busy||current()?.id==='draft-1';
  for(const id of ['save-srt','save-project','add'])$(id).disabled=!has||busy;
  $('transcript').disabled=!has||busy;$('cancel').disabled=!busy;
}
function download(blob,name){
  const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=name;
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
}
function safeName(s){return (s||'examclips').replace(/[^\p{L}\p{N}_-]+/gu,'_').slice(0,48)}
function current(){return clips[selected]}
function renderClips(){
  const holder=$('clips');holder.replaceChildren();
  if(!clips.length){holder.textContent='Нет клипов. Импортируйте SRT или запустите Whisper.';enable();return}
  clips.forEach((clip,i)=>{
    const btn=document.createElement('button');btn.className='clip'+(i===selected?' active':'');
    const n=document.createElement('span');n.className='clip-num';n.textContent=String(i+1).padStart(2,'0');
    const title=document.createElement('span');title.className='clip-name';title.textContent=clip.title;
    const duration=document.createElement('small');duration.textContent=timecode(clip.end-clip.start);
    btn.title=(clip.reviewReasons||[]).join('; ');
    btn.append(n,title,duration);btn.addEventListener('click',()=>{selected=i;sync()});holder.append(btn);
  });$('clip-count').textContent=String(clips.length);enable();
}
function sync(){
  renderClips();updateDashboard();renderQuiz();renderTimeline();const c=current();if(!c)return;
  $('selected-title').textContent='Микротема '+(selected+1);$('selected-time').textContent=timecode(c.end-c.start);
  $('approve-topic').textContent=c.status==='approved'
    ? '✓ Микротема проверена вручную · снять отметку'
    : '✓ Проверил вступление, объяснение и вывод';
  $('topic-review').textContent=c.reviewReasons?.length
    ? 'Проверить: '+c.reviewReasons.join(' · ')
    : 'Границы выбраны вручную. Проверьте вступление, объяснение и вывод.';

  $('review-state').textContent=!localReviewAvailable
    ? 'AI-проверка через установленную на ПК Ollama доступна только при локальном запуске. Для веб-версии используйте ручную проверку.'
    : c.llmReview
    ? 'Локальная модель: '+c.llmReview.verdict+' · '+c.llmReview.explanation+
      ' · Доказательства: '+(c.llmReview.evidence||[]).join(' | ')+
      ' · Это не гарантия качества — проверьте самостоятельно.'
    : 'Проверка завершённости через Ollama необязательна и выполняется только на этом компьютере.';
  $('clip-title').value=c.title;$('clip-start').value=c.start.toFixed(1);$('clip-end').value=c.end.toFixed(1);
  $('layout').value=c.layout;$('style-theme').value=c.scene?.theme||'warm';$('speaker-preset').value=c.speakerPreset||'auto';$('focus').value=c.focusX;$('focus-value').textContent=c.focusX+'%';
  $('player').currentTime=c.start;
  updateTimelinePlayhead();
}
function setBusy(v){busy=v;enable()}
async function selectFile(file){
  if(!file)return;
  if(file.size>2e9){status('Файл больше лимита MVP 2 ГБ');return}
  setBusy(true);status('Чтение локальных метаданных...');
  try{
    if(media)await media.input.dispose();
    if(originalUrl)URL.revokeObjectURL(originalUrl);
    media=await openMedia(file);originalUrl=URL.createObjectURL(file);$('player').src=originalUrl;
    sourceFile=file;sceneCuts=[];
    $('file-note').textContent=`${file.name} · ${timecode(media.duration)} · ${media.width}×${media.height} · ${(file.size/1e6).toFixed(1)} МБ`;
    // A draft is NOT an AI-generated completed lesson; only ASR/SRT can produce topic proposals.
    clips=[{id:'draft-1',start:0,end:Math.min(media.duration,180),title:'Черновик — сначала распознайте лекцию',
      layout:'hybrid',focusX:50,status:'needs-review',
      reviewReasons:['Нет транскрипта; это произвольный участок, а не законченная микротема']}];
    chunks=[];selected=0;$('transcript').value='';
    if(projectToRestore){
      const p=projectToRestore;projectToRestore=null;
      if(Math.abs(p.duration-media.duration)>2){status('Длительность видео не совпадает с проектом. Данные не импортированы.')}
      else{
        chunks=p.chunks||[];sceneCuts=Array.isArray(p.sceneCuts)?p.sceneCuts.filter(Number.isFinite):[];clips=p.clips.filter(c=>validRange(c.start,c.end,media.duration)).map((c,i)=>({...c,id:'clip-'+(i+1)}));
        $('transcript').value=toSrt(chunks);status('Проект восстановлен; проверьте ролики');
      }
    }else status('Видео открыто локально. Можете распознать речь или импортировать SRT.');
    setPhase(chunks.length?'results':'configure');
    sync();
    buildPrivateFilmstrip(media).catch(()=>{});
  }catch(e){media=null;clips=[];updateDashboard();renderQuiz();setPhase('upload');error(e)}finally{setBusy(false)}
}
$('video-file').addEventListener('change',e=>selectFile(e.target.files?.[0]));
$('drop').addEventListener('dragover',e=>{e.preventDefault();$('drop').classList.add('over')});
$('drop').addEventListener('dragleave',()=>$('drop').classList.remove('over'));
$('drop').addEventListener('drop',e=>{e.preventDefault();$('drop').classList.remove('over');selectFile(e.dataTransfer.files?.[0])});
$('import-srt').onclick=()=>$('srt-file').click();
$('srt-file').onchange=async e=>{
  if(!media)return;try{
    chunks=parseSrt(await e.target.files[0].text(),media.duration);
    if(!chunks.length)throw Error('Не найдены валидные интервалы SRT');
    proposeTopics();$('transcript').value=toSrt(chunks);setPhase('results');sync();
    status('SRT импортирован. Найдены кандидаты на законченные микротемы; проверьте их границы.');
  }catch(err){error(err)}
};
$('transcribe').onclick=async()=>{
  abort=new AbortController();setBusy(true);
  setPhase('processing');showOperation('prepare',null,'Подготавливаем Whisper…',{standalone:true});
  let key=null;
  try{
    const limit=$('asr-limit').value==='all'?Infinity:Number($('asr-limit').value);
    key=await checkpointKey(sourceFile,$('language').value+':'+$('asr-model').value);
    const previous=await loadCheckpoint(key,media.duration).catch(()=>null);
    if(previous?.completedWindows.length)status('Продолжаю распознавание: сохранено '+previous.completedWindows.length+' окон по 30 секунд.');
    chunks=await transcribe(media,{limit,language:$('language').value,
      onProgress:msg=>{
        status(msg);
        const m=String(msg).match(/Whisper:\s*(\d+)\s*\/\s*(\d+)\s*с/);
        if(m)showOperation('asr',100*Number(m[1])/Math.max(1,Number(m[2])),msg);
        else showOperation('prepare',null,msg);
      },signal:abort.signal,model:$('asr-model').value,resume:previous,
      onCheckpoint:async checkpoint=>saveCheckpoint(key,checkpoint)});
    if(!chunks.length)throw Error('Распознавание не вернуло речи. Попробуйте SRT или проверьте звук.');
    showOperation('topics',null,'Ищем законченные мысли в транскрипте…');
    proposeTopics();$('transcript').value=toSrt(chunks);setPhase('results');sync();
    status('Распознано '+chunks.length+' реплик. Кэш сохранён локально. Проверьте каждый предложенный микроурок.');
  }catch(e){
    if(key){
      const preserved=await loadCheckpoint(key,media.duration).catch(()=>null);
      if(preserved?.chunks?.length){chunks=preserved.chunks;proposeTopics();$('transcript').value=toSrt(chunks);sync()}
    }
    if(e.name==='AbortError')status('Остановлено: локальный прогресс сохранён, следующий запуск продолжит с контрольной точки.');
    else error(e);
    setPhase(chunks.length?'results':'configure');
  }finally{abort=null;setBusy(false)}
};
$('forget-asr').onclick=async()=>{
  if(!sourceFile)return;
  try{
    const key=await checkpointKey(sourceFile,$('language').value);
    await deleteCheckpoint(key);
    status('Локальный кэш Whisper удалён. Уже импортированные/отредактированные субтитры не изменены.');
  }catch(e){error(e)}
};

function proposeTopics(){
  if(!media||!chunks.length)return;
  const cfg=$('topic-preset').value==='compact'
    ? {min:60,target:105,max:180}
    : {min:60,target:165,max:300};
  const ideas=buildMicrotopics(chunks,media.duration,{...cfg,sceneCuts});
  if(ideas.length)clips=ideas;
  setPhase('results');
  selected=0;
  const report=coverageReport(chunks,media.duration);
  $('topic-coverage').textContent='Транскрипт до ~'+report.percent+'% длительности лекции. Найдено смен слайдов: '+sceneCuts.length+'. '+
   (report.partial?'Остальная часть НЕ проанализирована. Для всего видео выберите «Вся лекция». ':'')+
   'Это предварительные кандидаты: убедитесь, что каждый ролик понятен самостоятельно.';
  sync();
}
$('scan-chapters').onclick=async()=>{
 if(!media)return;
 abort=new AbortController();setBusy(true);
 try{
  status('Локальный анализ смен слайдов на протяжении лекции...');
  const cuts=await sampleSlideCuts(media,{start:0,end:media.duration},
    {sampleEvery:8,signal:abort.signal,onProgress:status});
  sceneCuts=cuts.filter(t=>t>0&&t<media.duration);
  if(chunks.length)proposeTopics();
  status('Визуальных смен: '+sceneCuts.length+'. Это признаки, а не доказанные границы микротем.');
 }catch(e){if(e.name==='AbortError')status('Анализ смен слайдов остановлен');else error(e)}
 finally{abort=null;setBusy(false)}
};
$('suggest-topics').onclick=()=>{proposeTopics();status('Микротемы пересчитаны по локальному транскрипту.')};
$('verify-topic').onclick=async()=>{
  const c=current();if(!media||!c||!chunks.length)return;
  setBusy(true);status('Локальная LLM изучает выбранную микротему и соседний контекст...');
  try{
    const payload=buildReviewPayload(c,chunks,media.duration);
    const response=await fetch('/api/local-review',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)});
    const result=await response.json();
    if(!response.ok)throw Error(result.error||'Локальная модель недоступна');
    c.llmReview=result;
    sync();
    status('LLM дала предварительную оценку: '+result.verdict+'. Проверьте цитаты и окончания.');
  }catch(e){
    $('review-state').textContent='Проверка недоступна: '+e.message+
      '. Для работы нужна локально запущенная Ollama; обычная нарезка продолжит работать.';
    status('Локальная проверка не выполнена; ручная оценка остаётся доступной');
  }finally{setBusy(false)}
};
$('apply-review').onclick=()=>{
  const c=current(),v=c?.llmReview;
  if(!c||!v?.evidenceVerified||!media)return;
  const a=Math.max(0,c.start+(v.suggestedStartDelta||0));
  const b=Math.min(media.duration,c.end+(v.suggestedEndDelta||0));
  if(b<=a||b-a>300){status('Изменение отвергнуто: ролик должен длиться не более 5 минут.');return}
  c.start=a;c.end=b;
  c.status='needs-review';delete c.approvedAt;
  c.reviewReasons=['Границы скорректированы по рекомендации LLM; требуется окончательная проверка.'];
  delete c.llmReview;sync();
  status('Границы изменены по вашему подтверждению. Проверьте получившийся урок.');
};
$('cancel').onclick=()=>abort?.abort();
for(const key of ['clip-title','clip-start','clip-end','layout','focus']){
  $(key).addEventListener('input',()=>{
    const c=current();if(!c||busy)return;
    const start=Number($('clip-start').value),end=Number($('clip-end').value);
    if(key==='clip-start'||key==='clip-end'){
      if(!validRange(start,end,media.duration)){status('Некорректные границы клипа');return}
      c.start=start;c.end=end;
    }
    c.title=$('clip-title').value;c.layout=$('layout').value;c.focusX=Number($('focus').value);
    // Any manual boundary edit invalidates prior LLM evidence for that interval.
    if(key==='clip-start'||key==='clip-end'||key==='clip-title'){
      delete c.llmReview;
      if(key==='clip-start'||key==='clip-end')delete c.scene;
      if(c.status==='approved'){c.status='needs-review';delete c.approvedAt;c.reviewReasons=['Содержимое изменилось: проверьте микротему заново.']}
      enable();
    }
    if(key==='clip-title'&&c.scene){
      c.scene.title=c.title;
      for(const chapter of c.scene.chapters||[])chapter.scene.title=c.title;
    }
    $('focus-value').textContent=c.focusX+'%';$('selected-time').textContent=timecode(c.end-c.start);
    renderClips();renderTimeline();
  });
}
$('transcript').addEventListener('change',()=>{
  if(!media)return;const parsed=parseSrt($('transcript').value,media.duration);
  if(parsed.length){chunks=parsed;enable();status('Субтитры обновлены. Для новой нарезки нажмите «Предложить микротемы».')}
  else status('Неверный SRT, прежняя разметка сохранена');
});
$('play-clip').onclick=()=>{const c=current();if(!c)return;$('player').currentTime=c.start;$('player').play()};
$('approve-topic').onclick=()=>{
 const c=current();if(!c||!media)return;
 if(c.status==='approved'){
   c.status='needs-review';
   c.reviewReasons=['Подтверждение снято.'];
 }else{
   c.status='approved';
   c.reviewReasons=[];
   c.approvedAt=new Date().toISOString();
 }
 sync();status(c.status==='approved'?'Микротема отмечена как проверенная автором.':'Отметка проверки снята.');
};
$('listen-context').onclick=()=>{
 const c=current();if(!c)return;
 $('player').currentTime=Math.max(0,c.start-15);
 $('player').play();
 status('Воспроизводятся 15 секунд перед началом, чтобы проверить контекст.');
};
for(const [key,side] of [['extend-start','start'],['extend-end','end']]){
 $(key).onclick=()=>{
  const c=current();if(!c||!media)return;
  if(side==='start')c.start=Math.max(0,c.start-15);
  else c.end=Math.min(media.duration,c.end+15);
  c.reviewReasons=['Граница изменена вручную. Проверьте её смысловую завершённость.'];
  c.status='needs-review';delete c.approvedAt;delete c.llmReview;
  sync();status('Временная граница изменена. Повторите предпросмотр.');
 };
}
$('player').addEventListener('timeupdate',()=>{const c=current();if(c&&!$('player').paused&&$('player').currentTime>=c.end)$('player').pause();updateTimelinePlayhead()});
$('add').onclick=()=>{
  if(!media)return;const last=current();
  const start=last?Math.min(media.duration-1,Math.max(0,last.end)):0;
  const end=Math.min(media.duration,start+60);
  clips.push({id:'microtopic-'+(clips.length+1),start,end,title:'Новая микротема (нужна проверка)',layout:'hybrid',focusX:50,reviewReasons:['Границы выбраны вручную']});
  selected=clips.length-1;sync()
};
$('remove').onclick=()=>{if(!clips.length)return;clips.splice(selected,1);selected=Math.max(0,Math.min(selected,clips.length-1));sync()};
$('save-srt').onclick=()=>download(new Blob([toSrt(chunks)],{type:'text/plain;charset=utf-8'}),'examclips.srt');
$('save-project').onclick=()=>{
  if(!media)return;const data={schema:1,videoName:media.input.source?.file?.name||$('video-file').files[0]?.name,duration:media.duration,clips,chunks,sceneCuts};
  download(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),'examclips.project.json');
};
$('load-project').onclick=()=>$('project-file').click();
$('project-file').onchange=async e=>{
  try{
    const data=JSON.parse(await e.target.files[0].text());
    if(data.schema!==1||!Array.isArray(data.clips)||!Array.isArray(data.chunks)||!Number.isFinite(data.duration))throw Error('Неизвестный формат проекта');
    projectToRestore=data;status('Теперь выберите исходный видеофайл этого проекта');
    if(media){await media.input.dispose();media=null;clips=[];$('player').removeAttribute('src');renderClips();enable()}
    $('video-file').click();
  }catch(err){error(err)}
};

const speakerPresets={
 right:{x:.80,y:.82,w:.20,h:.18},left:{x:0,y:.82,w:.20,h:.18},
 'top-right':{x:.80,y:0,w:.20,h:.18},
 'top-left':{x:0,y:0,w:.20,h:.18}
};
$('style-theme').onchange=()=>{
 const c=current();if(!c||!media)return;
 if(!c.scene)c.scene=makeStoryboard({width:media.width,height:media.height,duration:c.end-c.start});
 c.scene.theme=$('style-theme').value==='midnight'?'midnight':'warm';
 status('Визуальный стиль изменён, экспорт останется локальным');
};
$('speaker-preset').onchange=()=>{
 const c=current();if(!c||!media)return;
 c.speakerPreset=$('speaker-preset').value;
 if(!c.scene)c.scene=makeStoryboard({width:media.width,height:media.height,duration:c.end-c.start});
 const scenes=[c.scene,...(c.scene.chapters||[]).map(ch=>ch.scene)];
 for(const spec of scenes){
   if(speakerPresets[c.speakerPreset])spec.speaker={...speakerPresets[c.speakerPreset]};
   spec.hideSpeaker=c.speakerPreset==='none';
 }
 status('Область вебки обновлена локально');
};
$('analyze-scene').onclick=async()=>{
  const c=current();if(!media||!c)return;
  abort=new AbortController();setBusy(true);
  try{
    const lang=$('language').value==='ru'?'ru':'en';
    const {scene,recognizedLines,note,sceneCount,ocrBackend,context}=await analyzeScene(media,c,chunks,{language:lang,ocrEngine:$('ocr-engine').value,onProgress:status,signal:abort.signal});
    scene.theme=c.scene?.theme||'warm';c.scene=scene;c.layout='hybrid';c.speakerPreset='auto';$('speaker-preset').value='auto';$('layout').value='hybrid';
    $('scene-hint').textContent='Сцен: '+sceneCount+', областей: '+scene.panels.length+', OCR строк: '+recognizedLines+
      '. Движок OCR: '+ocrBackend+'. Содержание: '+(context?.kind||'unknown')+
      (context?.activeTab?' · активная вкладка: '+context.activeTab:'')+'. '+note;
    status('Композиция построена на устройстве. Проверьте схему, формулы и вебку.');
  }catch(e){if(e.name==='AbortError')status('Анализ отменён');else error(e)}
  finally{abort=null;setBusy(false)}
};
$('export-all').onclick=async()=>{
 if(!media||!clips.length||!chunks.length)return;
 if(typeof window.showDirectoryPicker!=='function'){
   status('Для пакетного экспорта выберите Chrome или Edge, поддерживающий выбор папки. Один MP4 можно сохранить отдельно.');
   return;
 }
 let dir;
 try{dir=await window.showDirectoryPicker({mode:'readwrite'})}
 catch(e){if(e.name!=='AbortError')error(e);return}
 const work=clips.filter(c=>c.id!=='draft-1').map(c=>structuredClone(c));
 if(!work.length)return;
 abort=new AbortController();setBusy(true);
 let exported=0;
 try{
   for(const clip of work){
     if(abort.signal.aborted)throw new DOMException('Stopped','AbortError');
     status('Экспорт '+(exported+1)+'/'+work.length+': '+clip.title);
     const blob=await exportClip(media,clip,chunks,{quality:$('output-quality').value,signal:abort.signal,
       onProgress:m=>status((exported+1)+'/'+work.length+' · '+m)});
     const name=String(exported+1).padStart(2,'0')+'_'+safeName(clip.title)+
       (clip.status==='approved'?'':'_DRAFT')+'.mp4';
     const handle=await dir.getFileHandle(name,{create:true});
     const writable=await handle.createWritable();
     try{await writable.write(blob);await writable.close()}
     catch(e){try{await writable.abort()}catch{}throw e}
     exported++;
   }
   status('Экспортировано '+exported+' микротем локально в выбранную папку.');
 }catch(e){
   if(e.name==='AbortError')status('Экспорт прерван; записано '+exported+' из '+work.length+' файлов.');
   else error(e);
 }finally{abort=null;setBusy(false)}
};
$('export').onclick=async()=>{
  const c=current();if(!media||!c)return;
  abort=new AbortController();setBusy(true);
  try{
    showOperation('composition',0,'Экспортируем вертикальное видео со звуком…');
    status('Кодирование MP4 со звуком. В зависимости от ПК может занять несколько минут...');
    const blob=await exportClip(media,c,chunks,{quality:$('output-quality').value,onProgress:msg=>{
      status(msg);
      const match=String(msg).match(/Видео\s+(\d+)\/(\d+)\s+кадров/);
      if(match)showOperation('composition',100*Number(match[1])/Number(match[2]),msg);
      else showOperation('composition',null,msg);
    },signal:abort.signal});
    download(blob,safeName(c.title)+(c.status==='approved'?'':'_DRAFT')+'.mp4');
    status('Экспорт завершён: '+(blob.size/1e6).toFixed(1)+' МБ');
  }catch(e){if(e.name==='AbortError')status('Экспорт остановлен');else error(e)}finally{abort=null;$('processing-panel').hidden=true;setBusy(false)}
};
function loop(){
  const video=$('player'),c=current();
  if(media&&c&&video.readyState>=2){
    const caption=captionSequenceAt(chunks,video.currentTime);
    try{paintFrame($('preview'),video,video.videoWidth,video.videoHeight,c.layout,c.focusX,caption,c.scene||null,Math.max(0,video.currentTime-c.start))}catch{}
  }
  previewRaf=requestAnimationFrame(loop);
}
initMvpEvents();loop();enable();updateDashboard();renderQuiz();probeLocalReview();
