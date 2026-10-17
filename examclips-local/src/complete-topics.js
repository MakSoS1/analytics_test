/**
 * Content-complete lecture editor: preserve every educational explanation,
 * even a 20+ minute worked exercise, without forcing a fixed number of shorts.
 *
 * No semantic AI claim: boundaries are EXTRACTIVE proposals based on explicitly
 * spoken topic markers and ASR time ranges; instructor reviews before exporting.
 * Filler and long ASR-detected silences are excluded, but uncertainty favours KEEP.
 */
import {normalizeChunks,titleFromText} from './segments.js';
import {tightSpeechPieces,sourceSegments,summarizeStoryPlan} from './selective-stories.js';
import {isNonTeachingIntroduction} from './lesson-screenplay.js';

const TRIVIAL=/^\s*(?:(?:ээ+|эм+|угу|ну|ага|ага-ага|okay|ok|um+|uh+|you know|ага да|да да)[\s.,!?]*){1,8}$/iu;
const ADMIN=/(?:проверка микрофона|слышно меня|настроим проектор|техническ(?:ие|ая) проблем|организационный момент|начн[её]м через|подождите минут|перерыв на|дожд[её]мся участников|расписание следующего занятия|can you hear me|microphone check|technical difficulties|we(?:'ll| will) take a break|like and subscribe)/iu;
const TEACHING=/(?:задач|решени|разбер|рассмотр|пример|формул|уравнен|доказа|алгоритм|теорем|потому что|объясн|причин|покаж|вычисл|эксперимент|результат|производн|интеграл|допустим|параметр|контейнер|сервис|balance|docker|example|formula|equation|solve|proof|demonstrat|reason|because|function|derive|implementation|let us calculate)/iu;
const STRONG_CHANGE=/^\s*(?:а\s+)?(?:теперь\s+(?:перейд[её]м|поговорим|рассмотрим|начн[её]м)\s+(?:к\s+)?(?:новой|другой|следующей)\s+(?:теме|задаче|части|вопросу)|следующая\s+(?:тема|задача|часть|глава)|новая\s+(?:тема|задача)|переходим\s+к\s+(?:другой|следующей|новой)\s+(?:теме|задаче)|moving on to (?:a |the )?(?:new|next|different) (?:topic|problem)|next (?:topic|problem|exercise)|let'?s move to a different topic)/iu;
const PRACTICE_BEGIN=/(?:решим\s+(?:эту|следующую|одну)?\s*задач|разбер[её]м\s+(?:задач|пример|упражнен)|практическ(?:ая|ую)\s+задач|докажем\s+теорем|условие\s+задач|find the solution|worked example|solve (?:the|this) (?:problem|exercise)|let'?s solve|proof of the theorem)/iu;
const PRACTICE_END=/(?:задач[ау]?\s+решен|ответ\s*(?:получ|равен|на\s+эту)|решение\s+найден|что\s+и\s+требовалось\s+доказать|мы\s+решили\s+задач|that completes (?:the|our) (?:proof|solution)|problem solved|final answer)/iu;
const TOPIC_TERMS=/[\p{L}\p{N}]{4,}/gu;
const STOP=new Set(('этого этом которая который которые сегодня теперь далее просто давайте тогда таким образом поэтому '+
 'иными словами потому также здесь значит можно будет нужно далее например this that with from they there and then '+
 'because therefore next what this given when example solution problem').split(/\s+/u));
function tokens(text){
 return new Set((String(text||'').toLowerCase().match(TOPIC_TERMS)||[])
  .filter(w=>!STOP.has(w)));
}
function similarity(a,b){
 const x=tokens(a),y=tokens(b);
 if(!x.size||!y.size)return .5;let common=0;for(const t of x)if(y.has(t))common++;
 return common/Math.sqrt(x.size*y.size);
}
/** Evidence-first: KEEP material unless unmistakably organizational or empty. */
export function isEducationalSpeech(text){
 const s=String(text||'').trim();
 if(!s||TRIVIAL.test(s)||isNonTeachingIntroduction(s))return false;
 if(ADMIN.test(s)&&!TEACHING.test(s))return false;
 return true;
}
function asClip(rows,index,duration){
 const beginning=rows[0].start,end=rows.at(-1).end;
 // Observe gaps, preserve short breathing pauses; never synthesize speech.
 const pieces=tightSpeechPieces(rows).map(x=>({
   start:Math.max(beginning,x.start),end:Math.min(end,x.end)
 })).filter(x=>x.end>x.start);
 const joined=rows.map(r=>r.text).join(' ');
 const words=joined.split(/\s+/u).filter(Boolean).length;
 const task=rows.some(r=>PRACTICE_BEGIN.test(r.text));
 const issues=['Автоматически предложены границы темы: проверьте связность и полноту объяснения'];
 if(pieces.length>1)issues.push('Удалены паузы по таймкодам речи; проверьте качество звуковых переходов');
 if(task)issues.push('Практическая задача оставлена целиком, даже если она длиннее обычного короткого видео');
 return {
   id:'topic-'+index,start:beginning,end,
   segments:pieces,
   title:titleFromText(rows.find(r=>TEACHING.test(r.text))?.text||joined),
   status:'needs-review',confidence:'low',method:'content-complete-extractive',
   layout:'hybrid',focusX:50,
   kind:task?'worked-exercise':'explanation',
   wordCount:words,outputSeconds:+pieces.reduce((n,p)=>n+p.end-p.start,0).toFixed(2),
   reviewReasons:issues
 };
}
/**
 * Accumulate ALL teaching rows in time order. Exclude only obvious filler and
 * long observed silence, never cut on a 1/2/5/20-minute clock or total budget.
 * Explicit new-topic transitions create boundaries; a running worked exercise
 * is kept together until the teacher concludes or clearly starts a NEW task.
 */
export function planCompleteTopics(chunks,duration,{sceneCuts=[]}={}){
 if(!Number.isFinite(duration)||duration<=0)
  return {clips:[],candidates:[],excluded:[],summary:summarizeStoryPlan([],0)};
 const all=normalizeChunks(chunks,duration);
 if(!all.length)return {clips:[],candidates:[],excluded:[],summary:summarizeStoryPlan([],duration)};
 const kept=[],excluded=[];
 for(const row of all){
   if(isEducationalSpeech(row.text))kept.push(row);
   else excluded.push({start:row.start,end:row.end,reason:'Очевидный организационный разговор или слова-паразиты'});
 }
 if(!kept.length)return {clips:[],candidates:[],excluded,summary:summarizeStoryPlan([],duration)};
 const groups=[];let current=[],practical=false,finished=false;
 const emit=()=>{if(current.length)groups.push(current);current=[];practical=false;finished=false};
 for(const row of kept){
   const explicit=STRONG_CHANGE.test(row.text);
   const newTask=PRACTICE_BEGIN.test(row.text);
   const gap=current.length?Math.max(0,row.start-current.at(-1).end):0;
   const prior=current.slice(-Math.min(current.length,5)).map(x=>x.text).join(' ');
   const clearlyDifferent=gap>150&&similarity(prior,row.text)<.10&&!practical&&current.length>0;
   // Within an active worked exercise steps/derivations should NOT cause new clips.
   // A second explicitly introduced problem begins a new completed lesson.
   const boundary=current.length>0&&(explicit||(newTask&&practical&&finished)||clearlyDifferent);
   if(boundary)emit();
   current.push(row);
   if(newTask)practical=true;
   if(PRACTICE_END.test(row.text))finished=true;
 }
 emit();
 const clips=groups.map((rows,i)=>asClip(rows,i+1,duration)).filter(c=>sourceSegments(c).length);
 const summary=summarizeStoryPlan(clips,duration);
 const candidateRows=groups.map((rows,i)=>({
   id:'candidate-'+(i+1),start:rows[0].start,end:rows.at(-1).end,
   text:rows.map(r=>r.text).join(' '),
   sourcePieces:tightSpeechPieces(rows),
   reason:'Полная содержательная тема, предварительная граница',score:1
 }));
 return {clips,candidates:candidateRows,excluded,
   summary:{...summary,excludedUtterances:excluded.length,
     processedUtterances:all.length,keptUtterances:kept.length,
     completionMode:'all-educational-speech',
     incompleteTranscript:kept.at(-1).end<duration-5}};
}
