/**
 * Editorial screenplay made FROM actual spoken source.
 * Evidence spans, not generated narration, are the sole input for video edits.
 * Checks "informative/not a biography", coherent theme and unfinished endings.
 */
import {sourceSegments} from './selective-stories.js';
const INTRO=/(?:меня зовут|мне \d{2} лет|я работаю|моя должность|я преподаю|мой стаж|немного о себе|пару слов о себе|биография|доцент кафедры|профессор кафедры|расписани[еяию] занятий|организационн[а-яё]* момент[а-яё]*|правил[а-яё]* курса|как будет проходить курс|сегодня познакомимся|записывайте мой email|записывайте мою почту|поставьте лайк|подпишитесь|my name is|i am a professor|i work at|my background|about myself|office hours|course schedule|welcome to the course)/iu;
const TEACH=/(?:почему|как работает|что происходит|например|поэтому|потому|разбер|реша|задач|формул|алгоритм|проверим|покажем|получается|следовательно|таким образом|вывод|доказа|конечно|docker|контейнер|образ|оркестрац|how|why|because|solve|example|result|algorithm|exercise)/iu;
const FINISH=/(?:итак|таким образом|мы получили|получили ответ|проверили результат|это объясняет|на этом задача|итог|вывод|мы доказали|therefore|conclusion|the result is|we solved|the solution is)/iu;
 // These are course agendas, not explanations of the named technologies.
 // Apply only to short, introductory utterances; otherwise preserve
 // ambiguous instructional speech for human review.
const AGENDA=/^\s*(?:(?:всем привет|здравствуйте|добрый день)[!.,\s]+)?(?:(?:ну|итак)[,.\s]+)?(?:сегодня|на сегодняшне[мй]\s+(?:занятии|лекции)|в этом (?:видео|уроке)|today|in this (?:lesson|lecture|video))[\s\S]{0,110}?(?:поговорим|рассмотрим|разбер[её]м|обсудим|изучим|познакомимся|будем\s+(?:изучать|рассматривать|обсуждать)|we(?:'ll| will)\s+(?:cover|discuss|learn|talk)|(?:we|you)\s+(?:are\s+going\s+to|will)\s+(?:learn|cover|talk)|cover|discuss|learn)/iu;
const EXPLANATION=/(?:потому что|то есть|например|следовательно|таким образом|означает|работает следующим образом|(?:контейнер[ыа]?|образ[ыа]?|docker)\s+(?:это|позволя(?:ет|ют))|because|for example|which means|therefore|is defined as)/iu;

const WORDS=/[\p{L}\p{N}]+/gu;
const tokenize=text=>String(text||'').toLowerCase().match(WORDS)||[];
export function isNonTeachingIntroduction(text){
 const s=String(text||'').trim();
 if(!s)return true;
 if(AGENDA.test(s)&&tokenize(s).length<=30&&!EXPLANATION.test(s))return true;
 const matches=[...s.matchAll(new RegExp(INTRO.source,'giu'))].length;
 // Source sentence containing an actual technical explanation is kept,
 // unless the entire sentence is primarily a biography/housekeeping.
 return matches>0&&(matches>=2||!TEACH.test(s)||tokenize(s).length<16);
}
export function inferEditorialBeats(clip,chunks){
 const sources=sourceSegments(clip);
 const related=(chunks||[]).filter(c=>sources.some(p=>c.end>p.start&&c.start<p.end));
 const narrative=related.filter(c=>!isNonTeachingIntroduction(c.text));
 const beats=narrative.map((c,i)=>({
   role:i===0?'intro':i===narrative.length-1&&FINISH.test(c.text)?'takeaway':'explanation',
   start:c.start,end:c.end,
   quote:String(c.text||'').trim(),source:'lecture'
 }));
 if(beats.length===1)beats[0].role='explanation';
 return beats;
}
/**
 * A compact editorial summary is NOT a transcript dump. Each summarized
 * statement is a short extractive restatement anchored to an unmodified
 * source quote, its exact time interval and an evidence identifier.
 * No unsupported conclusion is fabricated for an unfinished explanation.
 */
const DEFINITION=/(?:\b(?:is\s+(?:a|an|the)|are\s+(?:a|an)|means|refers\s+to|consists?\s+of|defined\s+as|unlike|different\s+from)\b|(?:это\s+|означает|называется|представляет\s+собой|в\s+отличие\s+от))/iu;
const EXAMPLE=/(?:\b(?:for\s+example|for\s+instance|let'?s\s+(?:look|take|run|try)|suppose|imagine|when\s+you\s+run)\b|например|допустим|к\s+примеру|рассмотрим\s+пример)/iu;
const CAUSE=/(?:\b(?:because|therefore|so\s+that|which\s+means|this\s+(?:allows|helps|prevents|reduces)|as\s+a\s+result|compared\s+to)\b|потому\s+что|поэтому|таким\s+образом|это\s+позволяет|следовательно)/iu;
const SUMMARY_LENGTH=240;
function conciseSource(text){
 const v=String(text||'').replace(/\s+/gu,' ').trim();
 const clauses=v.split(/(?<=[.!?])\s+/u).filter(Boolean);
 const meaningful=clauses.find(x=>DEFINITION.test(x)||CAUSE.test(x)||EXAMPLE.test(x))||clauses[0]||v;
 return meaningful.length<=SUMMARY_LENGTH?meaningful:meaningful.slice(0,SUMMARY_LENGTH).replace(/\s+\S*$/u,'').trim()+'…';
}
function selectDistinct(beats,count=5){
 const taken=new Set(),list=[];
 const best=predicate=>beats.findIndex((b,i)=>!taken.has(i)&&predicate(b.quote));
 const pick=(predicate,role)=>{
   const i=best(predicate);
   if(i<0)return;
   taken.add(i);
   list.push({...beats[i],role,sourceQuote:beats[i].quote});
 };
 pick(s=>DEFINITION.test(s),'definition');
 pick(s=>CAUSE.test(s),'mechanism');
 pick(s=>EXAMPLE.test(s),'example');
 pick(s=>FINISH.test(s),'takeaway');
 if(!list.length&&beats.length)pick(()=>true,'explanation');
 const important=beats.filter((b,i)=>!taken.has(i)&&tokenize(b.quote).length>=7);
 for(const b of important.slice(0,Math.max(0,count-list.length)))
   list.push({...b,role:'explanation',sourceQuote:b.quote});
 return list.slice(0,count).sort((a,b)=>a.start-b.start);
}
const LABELS={definition:'Что это',mechanism:'Как и почему работает',
 example:'Конкретный пример',takeaway:'Результат',explanation:'Ключевая мысль'};
function summaryBeats(clip,beats){
 const chosen=selectDistinct(beats);
 return chosen.map((b,i)=>({
   id:'evidence-'+(i+1),
   role:b.role,label:LABELS[b.role]||'Объяснение',
   text:conciseSource(b.quote),
   evidence:[{start:b.start,end:b.end,quote:b.quote,source:'lecture'}]
 }));
}
export function buildVerifiedLessonScreenplays(clips,chunks,{
 requireTranscriptEvidence=true
}={}){
 return (clips||[]).map((clip)=>{
   const beats=inferEditorialBeats(clip,chunks);
   const summary=summaryBeats(clip,beats);
   const material=beats.map(x=>x.quote).join(' ');
   const useful=beats.filter(b=>tokenize(b.quote).length>=5&&
     !isNonTeachingIntroduction(b.quote));
   const technical=useful.some(b=>TEACH.test(b.quote)||DEFINITION.test(b.quote)||CAUSE.test(b.quote));
   const finished=beats.some(b=>FINISH.test(b.quote));
   const minimum=tokenize(material).length>=15;
   const distinctSources=new Set(summary.flatMap(x=>x.evidence.map(e=>e.start)));
   const demonstrated=technical&&minimum&&distinctSources.size>=2;
   const endNearChapter=Number.isFinite(clip.chapter?.end)&&clip.chapter.end-clip.end<=25;
   // Slide transition alone can never prove an educational conclusion.
   const fullySupported=demonstrated&&(finished||summary.some(b=>b.role==='takeaway'));
   const issue=[];
   if(!minimum)issue.push('Недостаточно объяснения для самостоятельной микротемы');
   if(!technical)issue.push('Нет подтверждённого определения/механизма — проверьте, что это не вступление');
   if(!demonstrated)issue.push('Мало независимых исходных реплик для связного сценария');
   if(!fullySupported)issue.push('Явный итог не подтверждён речью: завершённость пока не доказана');
   const firstOriginal=beats.at(0)?.start??clip.start;
   const original=sourceSegments(clip),first=original.at(0);
   let pieces=original;
   if(first&&firstOriginal>first.start+.1&&firstOriginal<first.end&&original.length===1)
     pieces=[{start:firstOriginal,end:first.end}];
   const readyForReview=demonstrated;
   const screenplay={
     schema:2,
     heading:clip.title,
     summary,
     beats,
     quality:{evidenceCount:beats.length,technical,finished,
       readyForReview,fullySupported,chapterBoundary:endNearChapter,issues:issue},
     evidencePolicy:'Каждый тезис является сокращением исходной реплики; неподтверждённые выводы не добавляются'
   };
   return {
     ...clip,
     segments:pieces,start:Math.min(...pieces.map(x=>x.start)),
     end:Math.max(...pieces.map(x=>x.end)),
     screenplay,status:'needs-review',
     reviewReasons:[...new Set([...(clip.reviewReasons||[]),...issue])],
     editorialStatus:readyForReview?'proposed':'needs-more-context'
   };
 });
}
export function storyboardReadyForRendering(clip){
 return !!clip?.screenplay?.quality?.readyForReview&&
   (clip.screenplay.summary||clip.screenplay.beats||[])
     .every(b=>b.evidence?
       b.evidence.every(e=>e.source==='lecture'&&e.quote?.length>0&&e.end>e.start):
       b.source==='lecture'&&b.quote?.length>0);
}
