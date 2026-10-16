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
import {buildReviewPayload} from './completion-review.js';
import {checkpointKey,loadCheckpoint,saveCheckpoint,deleteCheckpoint} from './asr-checkpoint.js';
const root=document.querySelector('#app');
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
    <div class="settings">
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
    <div class="settings">
  <div class="heading">2. Найти микротемы</div>
  <label>Длительность<select id="topic-preset">
    <option value="full">Полная мысль · обычно 1–3 мин, максимум 5 мин</option>
    <option value="compact">Короткие объяснения · обычно 1–2 мин, максимум 3 мин</option>
  </select></label>
  <button id="scan-chapters" disabled>◫ Найти смены слайдов локально</button>
  <button id="suggest-topics" disabled>✧ Предложить законченные микротемы</button>
  <p class="hint" id="topic-coverage">Для смысловой нарезки нужна расшифровка речи. Рекомендации по границам предварительные: проверьте начало и вывод каждой микротемы.</p>
</div>
<div class="section-title">3. Готовые фрагменты <span id="clip-count">0</span></div>
    <div id="clips" class="clips"><p class="empty">После загрузки предложим фрагменты. Начальную и конечную границу можно изменять.</p></div>
  </aside>
  <section class="workspace" id="overview">
    <div class="workspace-top"><div><div class="eyebrow">ОБРАБОТКА ЛЕКЦИЙ · EXAMCLIPS</div><h1>Из лекции — в понятные короткие видео</h1><p class="lead">Текст, формулы и слайды остаются в кадре. Монтаж и расшифровка выполняются на устройстве.</p></div><span class="status" id="status">Ожидание видео</span></div>
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
let media=null,sourceFile=null,originalUrl=null,clips=[],chunks=[],sceneCuts=[],selected=0,busy=false,abort=null,previewRaf=0,projectToRestore=null;
function status(msg){$('progress').textContent=msg;$('status').textContent=msg.slice(0,48)}
function error(e){console.error(e);status('Ошибка: '+(e.message||String(e)))}
function enable(){
  const has=!!media,clip=!!clips.length;
  $('transcribe').disabled=!has||busy;$('import-srt').disabled=!has||busy;
  $('scan-chapters').disabled=!has||busy;
  $('forget-asr').disabled=!has||busy;
  $('suggest-topics').disabled=!has||busy||!chunks.length;
  $('export-all').disabled=!has||busy||!chunks.length||clips.every(c=>c.id==='draft-1');
  $('verify-topic').disabled=!clip||busy||!chunks.length||current()?.id==='draft-1';
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
  renderClips();const c=current();if(!c)return;
  $('selected-title').textContent='Микротема '+(selected+1);$('selected-time').textContent=timecode(c.end-c.start);
  $('approve-topic').textContent=c.status==='approved'
    ? '✓ Микротема проверена вручную · снять отметку'
    : '✓ Проверил вступление, объяснение и вывод';
  $('topic-review').textContent=c.reviewReasons?.length
    ? 'Проверить: '+c.reviewReasons.join(' · ')
    : 'Границы выбраны вручную. Проверьте вступление, объяснение и вывод.';

  $('review-state').textContent=c.llmReview
    ? 'Локальная модель: '+c.llmReview.verdict+' · '+c.llmReview.explanation+
      ' · Доказательства: '+(c.llmReview.evidence||[]).join(' | ')+
      ' · Это не гарантия качества — проверьте самостоятельно.'
    : 'Проверка завершённости через Ollama необязательна и выполняется только на этом компьютере.';
  $('clip-title').value=c.title;$('clip-start').value=c.start.toFixed(1);$('clip-end').value=c.end.toFixed(1);
  $('layout').value=c.layout;$('style-theme').value=c.scene?.theme||'warm';$('speaker-preset').value=c.speakerPreset||'auto';$('focus').value=c.focusX;$('focus-value').textContent=c.focusX+'%';
  $('player').currentTime=c.start;
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
    sync();
  }catch(e){media=null;clips=[];error(e)}finally{setBusy(false)}
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
    proposeTopics();$('transcript').value=toSrt(chunks);sync();
    status('SRT импортирован. Найдены кандидаты на законченные микротемы; проверьте их границы.');
  }catch(err){error(err)}
};
$('transcribe').onclick=async()=>{
  abort=new AbortController();setBusy(true);
  let key=null;
  try{
    const limit=$('asr-limit').value==='all'?Infinity:Number($('asr-limit').value);
    key=await checkpointKey(sourceFile,$('language').value+':'+$('asr-model').value);
    const previous=await loadCheckpoint(key,media.duration).catch(()=>null);
    if(previous?.completedWindows.length)status('Продолжаю распознавание: сохранено '+previous.completedWindows.length+' окон по 30 секунд.');
    chunks=await transcribe(media,{limit,language:$('language').value,
      onProgress:status,signal:abort.signal,model:$('asr-model').value,resume:previous,
      onCheckpoint:async checkpoint=>saveCheckpoint(key,checkpoint)});
    if(!chunks.length)throw Error('Распознавание не вернуло речи. Попробуйте SRT или проверьте звук.');
    proposeTopics();$('transcript').value=toSrt(chunks);sync();
    status('Распознано '+chunks.length+' реплик. Кэш сохранён локально. Проверьте каждый предложенный микроурок.');
  }catch(e){
    if(key){
      const preserved=await loadCheckpoint(key,media.duration).catch(()=>null);
      if(preserved?.chunks?.length){chunks=preserved.chunks;proposeTopics();$('transcript').value=toSrt(chunks);sync()}
    }
    if(e.name==='AbortError')status('Остановлено: локальный прогресс сохранён, следующий запуск продолжит с контрольной точки.');
    else error(e);
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
      if(c.status==='approved'){c.status='needs-review';delete c.approvedAt;c.reviewReasons=['Содержимое изменилось: проверьте микротему заново.']}
      enable();
    }
    if(key==='clip-title'&&c.scene){
      c.scene.title=c.title;
      for(const chapter of c.scene.chapters||[])chapter.scene.title=c.title;
    }
    $('focus-value').textContent=c.focusX+'%';$('selected-time').textContent=timecode(c.end-c.start);
    renderClips();
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
$('player').addEventListener('timeupdate',()=>{const c=current();if(c&&!$('player').paused&&$('player').currentTime>=c.end)$('player').pause()});
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
    status('Кодирование MP4 со звуком. В зависимости от ПК может занять несколько минут...');
    const blob=await exportClip(media,c,chunks,{quality:$('output-quality').value,onProgress:status,signal:abort.signal});
    download(blob,safeName(c.title)+(c.status==='approved'?'':'_DRAFT')+'.mp4');
    status('Экспорт завершён: '+(blob.size/1e6).toFixed(1)+' МБ');
  }catch(e){if(e.name==='AbortError')status('Экспорт остановлен');else error(e)}finally{abort=null;setBusy(false)}
};
function loop(){
  const video=$('player'),c=current();
  if(media&&c&&video.readyState>=2){
    const caption=captionCueAt(chunks,video.currentTime);
    try{paintFrame($('preview'),video,video.videoWidth,video.videoHeight,c.layout,c.focusX,caption,c.scene||null,Math.max(0,video.currentTime-c.start))}catch{}
  }
  previewRaf=requestAnimationFrame(loop);
}
loop();enable();
