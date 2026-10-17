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
export function buildVerifiedLessonScreenplays(clips,chunks,{
  requireTranscriptEvidence=true
}={}){
 return (clips||[]).map((clip,i)=>{
   const beats=inferEditorialBeats(clip,chunks);
   const material=beats.map(x=>x.quote).join(' ');
   const useful=beats.filter(b=>tokenize(b.quote).length>=5&&
     (!isNonTeachingIntroduction(b.quote)||TEACH.test(b.quote)));
   const technical=useful.some(b=>TEACH.test(b.quote));
   const finished=beats.some(b=>FINISH.test(b.quote));
   const minimum=tokenize(material).length>=15;
   const issue=[];
   if(!minimum)issue.push('Недостаточно речи, чтобы подтвердить самостоятельную микротему');
   if(!technical)issue.push('Не обнаружено предметного объяснения: проверьте, что это не вводная часть');
   if(!finished)issue.push('В расшифровке не найден явный итог — проверьте завершённость');
   const firstOriginal=beats.at(0)?.start??clip.start;
   const original=sourceSegments(clip),first=original.at(0);
   let pieces=original;
   // Trim standalone intro before first evidence, never removing a valid
   // explanation from the clip. Avoid altering a clip with >1 source piece.
   if(first&&firstOriginal>first.start+.1&&firstOriginal<first.end&&original.length===1){
     pieces=[{start:firstOriginal,end:first.end}];
   }
   const approvedForProposal=minimum&&technical;
   return {
     ...clip,
     segments:pieces,start:Math.min(...pieces.map(x=>x.start)),end:Math.max(...pieces.map(x=>x.end)),
     screenplay:{schema:1,beats,quality:{
       evidenceCount:beats.length,technical,finished,readyForReview:approvedForProposal,
       issues:issue
     }},
     status:'needs-review',
     reviewReasons:[...new Set([...(clip.reviewReasons||[]),...issue])],
     editorialStatus:approvedForProposal?'proposed':'needs-more-context'
   };
 });
}
export function storyboardReadyForRendering(clip){
 return !!clip?.screenplay?.quality?.readyForReview&&
   (clip.screenplay.beats||[]).every(b=>b.source==='lecture'&&b.quote?.length>0);
}
