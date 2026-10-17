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
import {isLectureHousekeeping,meaningfulTitle,topicEvidence} from './lecture-semantics.js';
import {normalizeSlideChapters,chapterForTime,visualBoundaryBetween} from './lecture-outline.js';
import {dedupeTranscriptRows,consolidateMicrotopics,assignExclusiveSource} from './topic-editorial-guardrails.js';
import {lessonIdentity,rowLessonIdentity,resolvedChapterKey} from './lesson-identity.js';
import {refineSubtopics} from './semantic-subtopics.js';
import {applyVisualSubtopicGuides} from './visual-subtopic-hints.js';

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
 if(!s||TRIVIAL.test(s)||isLectureHousekeeping(s)||isNonTeachingIntroduction(s))return false;
 if(ADMIN.test(s)&&!TEACHING.test(s))return false;
 return true;
}
function groupConceptHeading(rows,chapter){
 const identity=lessonIdentity(rows,chapter);
 // Only evidence from technical speech can override the slide chapter.
 // A generic "Docker" or "container" must NEVER name a Dockerfile clip.
 if(identity?.title)return identity.title;
 return meaningfulTitle(rows);
}
function asClip(rows,index,duration,chapter=null,{verifiedTitle=null,verifiedConcept=null,visualTitle=null,visualSection=null}={}){
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
   segments:pieces,chapter:chapter?{title:chapter.title,key:chapter.key,source:chapter.source,start:chapter.start,end:chapter.end}:null,
   thumbnailTime:beginning+Math.min(6,(end-beginning)*.2),
   title:verifiedTitle||visualTitle||groupConceptHeading(rows,chapter),
   verifiedConcept:verifiedConcept||null,
   visualSection:visualSection||null,
   visualBasis:visualTitle?'Кадры лекции + совпадения терминов с речью; окончательные границы требуют проверки':null,
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
/**
 * Book-style planning: first assign time-ordered teaching utterances to
 * chapters (visual hints / slide headings), then find sustained concept
 * changes INSIDE each chapter. Do not create a clip for chapter names alone.
 * No fixed output count, percentage, or arbitrary duration-based cut.
 */
function concept(row,chapter){
 const t=String(row.text||'');
 const inferred=topicEvidence(t);
 if(resolvedChapterKey(chapter)==='dockerfile')return rowLessonIdentity(row,chapter)?.key||'dockerfile-general';
 if(/\b(?:what\s+is\s+(?:a\s+)?container|containers?\s+(?:are|is)|контейнер\s+это)\b/iu.test(t)&&
    !/\b(?:virtual\s+machines?|vm\b|hypervisor)\b/iu.test(t))
   return 'container-definition';
 if(/\b(?:difference\s+between\s+containers?\s+and\s+(?:virtual\s+machines?|vms?)|versus\s+(?:vm|virtual)|vs\.?\s+(?:vm|virtual)|отлич\w+\s+от\s+виртуальн)/iu.test(t))
   return 'virtual-machines';
 if(/\b(?:cache\s+layer|cache\s+invalid|docker\s+build\s+cache|кеширован\w*\s+сло)/iu.test(t))
   return 'docker-build-cache';
 if(/\b(?:multi.?stage|multiple\s+stages|нескольк\w*\s+этап\w*\s+сборк)/iu.test(t))
   return 'docker-multistage';
 if(/\b(?:bridge\s+networks?|docker\s+bridge|default\s+bridge|bridge\s+mode)/iu.test(t))return 'docker-bridge';
 if(/\b(?:overlay\s+networks?|docker\s+overlay|overlay\s+mode)/iu.test(t))return 'docker-overlay';
 if(/\b(?:host\s+networks?|network\s+host|network\s+none)/iu.test(t))return 'docker-host';
 if(/\b(?:resource\s+limits?|cpu\s+limits?|memory\s+limits?|cgroups?)/iu.test(t))return 'resource-limits';
 return inferred?.key==='docker-containers'?(chapter?.key||null):(inferred?.key||chapter?.key||null);
}
const CONTENT_START=/(?:\b(?:what\s+is\s+a\s+container|containers?\s+(?:are|is)|virtual\s+machines?\s+(?:are|is)|docker\s+(?:uses|allows)|for\s+example|because|means\s+that|in\s+contrast)\b|\b(?:что\s+такое|контейнер\s+это|например|потому\s+что|в\s+отличие\s+от)\b)/iu;
function genericOpeningSkip(rows,duration){
 // For ordinary short instructional recordings, do not enforce a time-based
 // introductory exclusion. Look for consecutive introductory-language rows.
 if(duration<150||rows.length<5)return 0;
 let intro=0;
 for(const c of rows){
   if(c.start>Math.min(360,duration*.2))break;
   if(isLectureHousekeeping(c.text)||isNonTeachingIntroduction(c.text)){
     intro=Math.max(intro,c.end);continue;
   }
   if(CONTENT_START.test(c.text))break;
   // Generic presenter/plan speech without examples is not convincing learning.
   const terms=(c.text.match(/[\p{L}\p{N}]{4,}/gu)||[]).length;
   if(c.start<180&&terms<7){intro=Math.max(intro,c.end);continue}
   break;
 }
 return intro;
}
function splitChapter(rows,chapter,sceneCuts){
 const groups=[];let current=[],practical=false,finished=false;
 const emit=()=>{if(current.length)groups.push(current);current=[];practical=false;finished=false};
 for(let i=0;i<rows.length;i++){
  const row=rows[i],prev=current.at(-1),gap=prev?Math.max(0,row.start-prev.end):0;
  const explicit=STRONG_CHANGE.test(row.text),newTask=PRACTICE_BEGIN.test(row.text);
  const prior=current.slice(-Math.min(5,current.length)).map(x=>x.text).join(' ');
  const clearlyDifferent=gap>100&&similarity(prior,row.text)<.08&&!practical;
  const recent=current.slice(-4).map(x=>concept(x,chapter)).filter(Boolean);
  const stable=recent.length>=2&&recent.slice(-2).every(x=>x===recent.at(-1));
  const next=concept(row,chapter);
  const nextNext=rows.slice(i,i+3).map(x=>concept(x,chapter)).filter(Boolean);
  const repeated=next&&nextNext.filter(x=>x===next).length>=2;
  const transitionIdentity=rowLessonIdentity(row,chapter);
  const moved=stable&&next&&next!==recent.at(-1)&&next!=='docker-containers'&&
    transitionIdentity?.specific&&repeated&&
    (prev.end-current[0].start>=32)&&
    (rows[Math.min(rows.length-1,i+2)].end-row.start>=20);
  const visual=prev?sceneCuts.some(t=>Math.abs(t-row.start)<8&&
    prev.start+15<row.start):false;
  // Compare sustained adjacent explanations, not isolated terms.
  const before=rows.slice(Math.max(0,i-3),i).map(r=>r.text).join(' ');
  const after=rows.slice(i,i+3).map(r=>r.text).join(' ');
  const coherentBefore=i>=4?similarity(rows.slice(Math.max(0,i-6),i-3).map(r=>r.text).join(' '),before):0;
  const coherentAfter=i+4<rows.length?similarity(after,rows.slice(i+3,i+6).map(r=>r.text).join(' ')):0;
  const strongShift=!!(current.length>=3&&row.start-current[0].start>=55&&
    similarity(before,after)<.10&&coherentBefore>.13&&coherentAfter>.13);
  // A noun mentioned once isn't a new lesson. Require sustained explanation
  // and either specific new evidence or a real visual/announced transition.
  const topical=!!(!practical&&current.length>=2&&
    ((moved&&prev.end-current[0].start>=32)||
     (strongShift&&visual&&rows[Math.min(rows.length-1,i+2)].end-row.start>=20)));
  const boundary=!!(current.length&&(explicit||(newTask&&practical&&finished)||
    clearlyDifferent||(!practical&&topical)));
  if(boundary)emit();
  current.push(row);
  if(newTask)practical=true;
  if(PRACTICE_END.test(row.text))finished=true;
 }
 emit();
 return groups;
}
/**
 * Outline chapters come from slide OCR or a validated per-video reference.
 * Scene cuts alone are weak evidence: they never create arbitrary stories.
 */
export function planCompleteTopics(chunks,duration,{sceneCuts=[],chapters=[],visualHints=[]}={}){
 if(!Number.isFinite(duration)||duration<=0)
  return {clips:[],candidates:[],excluded:[],summary:summarizeStoryPlan([],0)};
 const all=normalizeChunks(chunks,duration);
 const deDuplicated=dedupeTranscriptRows(all);
 if(!all.length)return {clips:[],candidates:[],excluded:[],summary:summarizeStoryPlan([],duration)};
 const outline=normalizeSlideChapters(chapters,duration);
 const beginning=outline.length?0:genericOpeningSkip(all,duration);
 const kept=[],excluded=[...deDuplicated.removed];
 for(const row of deDuplicated.rows){
  const chapter=chapterForTime(outline,(row.start+row.end)/2);
  if(chapter?.key==='introduction'||(beginning>0&&row.end<=beginning)||
    !isEducationalSpeech(row.text)){
   excluded.push({start:row.start,end:row.end,reason:chapter?.key==='introduction'?
     'Вступление/биография/план занятия (визуально подтверждено)':
     'Организационная или неинформативная речь'});
  }else kept.push(row);
 }
 if(!kept.length)return {clips:[],candidates:[],excluded,summary:summarizeStoryPlan([],duration)};
 const chapterGroups=[];let bucket=[],owner=null;
 const emit=()=>{if(bucket.length)chapterGroups.push({rows:bucket,chapter:owner});bucket=[]};
 for(const row of kept){
  const chapter=chapterForTime(outline,(row.start+row.end)/2);
  const chapterId=chapter?.start??null;
  const priorId=owner?.start??null;
  const prev=bucket.at(-1);
  const chapterChanged=bucket.length>0&&chapterId!==priorId;
  const nearbyBoundary=prev&&visualBoundaryBetween(outline,prev,row);
  // A known slide-title transition ends the previous chapter, not just a
  // timer tick. If ASR skipped the slide transition, the speech still aligns.
  if(chapterChanged||nearbyBoundary)emit();
  bucket.push(row);owner=chapter;
 }
 emit();
 const groups=[];
 for(const {rows,chapter} of chapterGroups)
  for(const group of splitChapter(rows,chapter,sceneCuts))
    groups.push({rows:group,chapter});
 const visuallyAligned=applyVisualSubtopicGuides(groups,visualHints);
 const finer=refineSubtopics(visuallyAligned);
 const refined=consolidateMicrotopics(finer);
 excluded.push(...refined.omitted);
 const clips=assignExclusiveSource(refined.groups.map(({rows,chapter,editorialNotes,verifiedTitle,verifiedConcept,visualTitle,visualSection},i)=>{
  const clip=asClip(rows,i+1,duration,chapter,{verifiedTitle,verifiedConcept,visualTitle,visualSection});
  if(editorialNotes?.length)clip.reviewReasons.push(...editorialNotes);
  return clip;
 })).filter(c=>sourceSegments(c).length&&c.outputSeconds>=12);
 const summary=summarizeStoryPlan(clips,duration);
 const candidateRows=refined.groups.map(({rows,chapter},i)=>({
   id:'candidate-'+(i+1),start:rows[0].start,end:rows.at(-1).end,
   text:rows.map(r=>r.text).join(' '),
   chapter:chapter?.title||null,sourcePieces:tightSpeechPieces(rows),
   reason:'Учебная микротема в последовательной главе',score:1
 }));
 return {clips,candidates:candidateRows,excluded,chapters:outline,
  summary:{...summary,excludedUtterances:excluded.length,
   processedUtterances:all.length,keptUtterances:Math.max(0,kept.length-refined.omitted.length),
   completionMode:'hierarchical-reviewed',
   chapters:chapterGroups.length,
   rawTopicCandidates:groups.length,
   semanticSubtopicCandidates:finer.length,
   evidencedSubtopicSplits:Math.max(0,finer.length-groups.length),
   visualSubtopicCandidates:visuallyAligned.length,
   visualEvidenceSplitCount:Math.max(0,visuallyAligned.length-groups.length),
   editorialMerges:refined.mergedCount,
   duplicateUtterances:deDuplicated.removed.length,
   rejectedFragments:refined.omitted.length,
   nonOverlappingSource:true,
   excludedIntroSeconds:+excluded.filter(x=>x.reason.includes('Вступление'))
    .reduce((n,x)=>n+x.end-x.start,0).toFixed(2),
   incompleteTranscript:kept.at(-1).end<duration-5}};
}
