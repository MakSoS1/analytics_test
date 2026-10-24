/** Local, subject-independent sentence/discourse segmenter. No source identity,
 * topic dictionary, required clip count or maximum lesson duration.
 */
import {normalizeChunks} from './segments.js';
import {joinSpeechSentences,sentenceEnded} from './speech-boundaries.js';
import {isEducationalSpeech} from './complete-topics.js';
import {dedupeTranscriptRows,assignExclusiveSource} from './topic-editorial-guardrails.js';
import {tightSpeechPieces,summarizeStoryPlan} from './selective-stories.js';
const STOP=new Set(`this that these those they them their there here what which where when why how have has had were was are will would could should shall does did can may might must your our you the and but for with from into then than also just only very really about because therefore example first second third next now okay well let's let us its it's это этой этого этот эти как что чтобы когда который которая которые для или при уже ещё еще также потому поэтому например теперь значит очень будет было были есть вот так мы вы они она оно его их это`.split(/\s+/u));
const terms=text=>(String(text).toLowerCase().match(/[\p{L}\p{N}][\p{L}\p{N}-]{2,}/gu)||[]).filter(t=>!STOP.has(t));
// These are discourse actions, independent of the nouns being taught.
const transitionCue=text=>/^\s*(?:(?:okay|well|so|and|итак|хорошо)[,.]?\s+)*(?:now[, ]+(?:let(?:'s| us)\s+)?(?:talk|discuss|look at|consider|move|turn|before|a quick|the other half)|let(?:'s| us)\s+(?:talk|discuss|move|turn)|(?:the\s+)?next\s+(?:one|topic|question|concept)|(?:and\s+)?finally|moving on|теперь\s+(?:рассмотрим|поговорим|обсудим|перейд[её]м)|следующ(?:ая|ий|ее)\s+(?:тема|вопрос|понятие)|перейд[её]м\s+к|here(?:'s| is) the (?:truth|problem|question)|let(?:'s| us) (?:start with|go to)|do you have (?:any )?questions|есть ли вопросы|let me leave you with|to summarize|in summary|подвед[её]м итог)/iu.test(text);
export function announcesTopic(text){
 const t=String(text).replace(/^(?:PROFESSOR|INSTRUCTOR|STUDENT|SPEAKER(?: \d+)?)\s*:\s*/u,'');
 if(/(?:look at|consider) (?:this|that|the (?:graph|diagram|same|result|version))|now before[,.]?\s+let me/iu.test(t))return false;
 return transitionCue(t)||/^(?:so[, ]+)?(?:let(?:'s| us) (?:do|work through) (?:an?|the next) example|example \d+|here(?:'s| is) (?:here )?how|рассмотрим (?:следующий )?пример)/iu.test(t);
}
const DEPENDENT=/^\s*(?:because|which|that|this|these|those|it|they|them|therefore|however|so\b|and\b|but\b|because|потому|поэтому|это\b|этот\b|эта\b|они\b|он\b|она\b|значит\b|следовательно\b)/iu;
const PRACTICE=/(?:let(?:'s| us) do (?:an?|the next) example|example \d+|worked example|let(?:'s| us) solve|solve (?:this|the) (?:problem|exercise)|before we compare|решим\s+(?:эту\s+)?задачу|разбер[её]м\s+пример|докажем)/iu;
const COMPLETED=/(?:problem solved|that completes|final answer|the result is|задача решена|получили ответ|что и требовалось доказать)/iu;
const span=rows=>rows.length?rows.at(-1).end-rows[0].start:0;
function titleFor(rows,chapter){
 const first=rows.slice(0,8).map(r=>r.text.trim());
 const shortHeading=/^(?:and|now)[, ]+[\p{L}-]+[.!]$/iu.test(first[0])?first[0]:null;
 const announced=announcesTopic(first[0])?first[0]:null;
 let text=shortHeading||announced||chapter?.title||first.find(s=>terms(s).length>=3)||first[0]||'Фрагмент лекции';
 text=text.replace(/^\s*(?:(?:okay|well|so|and|итак|хорошо)[,.]?\s+)*/iu,'')
  .replace(/^(?:now[, ]+)?(?:let(?:'s| us)\s+)?(?:talk about|discuss|look at|consider|move (?:on )?to|turn to|go to|start with)\s+/iu,'')
  .replace(/^(?:the )?next one is\s+/iu,'')
  .replace(/^(?:теперь\s+)?(?:рассмотрим|поговорим о|обсудим|перейд[её]м к)\s+/iu,'');
 const clarification=text.match(/clarification about (.+?)(?:,| because|$)/iu);
 if(clarification)text=clarification[1];
 // Vague transitions are not useful titles: quote the following actual subject.
 if(/most powerful technique|other half|here (?:is|s) the truth|here's the truth|let'?s move on|what came before/iu.test(text)){
  text=first.slice(1).find(s=>/^(?:it'?s|this is)\s+/iu.test(s))?.replace(/^(?:it'?s|this is)\s+/iu,'')||chapter?.title||first[1]||text;
  if(/other half/iu.test(first[0]))text=first[1]||text;
 }
 const rule=first.find(s=>/^everything about .+ comes down/iu.test(s));
 if(rule)text=rule.replace(/^everything about /iu,'').replace(/ comes down.*$/iu,'');
 text=text.replace(/\s+/gu,' ').replace(/[.!?]+$/u,'');
 return text.length<=110?text:text.slice(0,110).replace(/\s+\S*$/u,'')+'…';
}

export function planGeneralTopics(chunks,duration,{sceneCuts=[],chapters=[]}={}){
 const raw=normalizeChunks(chunks,duration);
 if(!raw.length)return {clips:[],candidates:[],excluded:[],summary:summarizeStoryPlan([],duration)};
 const clean=dedupeTranscriptRows(raw),sentences=joinSpeechSentences(clean.rows);
 // Filter complete sentence units, never a line that may be the first half of a sentence.
 const alignedChapters=chapters.map((ch,index)=>{
  const nearby=sentences.filter(r=>Math.abs(r.start-ch.start)<=22&&(!DEPENDENT.test(r.text)||announcesTopic(r.text)));
  const announced=nearby.filter(r=>announcesTopic(r.text)||/^(?:let(?:'s| us) start|what\b|что\b)/iu.test(r.text));
  const best=(announced.length?announced:nearby).sort((a,b)=>Math.abs(a.start-ch.start)-Math.abs(b.start-ch.start))[0];
  const key=s=>String(s).toLowerCase().match(/[\p{L}]+/gu)?.slice(0,3).join(' ');
  return {...ch,start:index===0&&ch.key==='introduction'?0:best?.start??ch.start,returned:chapters.slice(0,index).some(prior=>key(prior.title)===key(ch.title))};
 }).sort((a,b)=>a.start-b.start);
 alignedChapters.forEach((ch,i)=>{ch.end=alignedChapters[i+1]?.start??duration});
 const excluded=[...clean.removed],units=[];
 for(const row of sentences){
  const ch=alignedChapters.find(c=>row.start>=c.start&&row.start<c.end);
  const speech=row.text.replace(/^(?:PROFESSOR|INSTRUCTOR|STUDENT|SPEAKER(?: \d+)?)\s*:\s*/u,'');
  const publisher=row.start<60&&/following content is provided|support.*(?:open.?courseware|donation)|make a donation|visit mit opencourseware|creative commons license/iu.test(speech);
  if(!publisher&&isEducationalSpeech(speech)&&ch?.key!=='introduction')units.push(row);
  else excluded.push({...row,reason:'Организационная речь или пустая реплика'});
 }
 const documentFrequency=new Map();
 for(const u of units)for(const t of new Set(terms(u.text)))documentFrequency.set(t,(documentFrequency.get(t)||0)+1);
 const vector=rows=>{const m=new Map();for(const r of rows)for(const t of terms(r.text))m.set(t,(m.get(t)||0)+1);return m};
 const similarity=(a,b)=>{const x=vector(a),y=vector(b);let dot=0,xx=0,yy=0;
  const w=t=>Math.log(1+units.length/(1+(documentFrequency.get(t)||0)));
  for(const [t,n] of x){const a=Math.sqrt(n)*w(t);xx+=a*a;dot+=a*Math.sqrt(y.get(t)||0)*w(t)}
  for(const [t,n] of y)yy+=n*w(t)**2;
  return xx&&yy?dot/Math.sqrt(xx*yy):0;
 };
 const groups=[];let current=[],practice=false;
 const emit=()=>{if(current.length)groups.push(current);current=[];practice=false};
 for(let i=0;i<units.length;i++){
  const row=units[i],prev=current.at(-1),at=row.start;
  const before=current.filter(r=>r.end>=at-50),after=units.slice(i).filter(r=>r.start<=at+50);
  const leftEnough=span(current)>=28&&terms(current.map(r=>r.text).join(' ')).length>=10;
  const rightEnough=span(after)>=20&&terms(after.map(r=>r.text).join(' ')).length>=10;
  const announce=announcesTopic(row.text);
  const shortHeading=/^(?:and|now)[, ]+[\p{L}-]+[.!]$/iu.test(row.text)&&terms(row.text).length===1&&span(current)>60;
  const listItem=/^(?:(?:and|the)\s+)*(?:next one|first one|second|third)/iu.test(row.text);
  const enumerating=current.slice(0,12).some(r=>/\b(?:states|steps|options|stages|types|cases)\b|(?:состояни|шага|шагов|вариант|этап)/iu.test(r.text));
  const chapterChange=alignedChapters.some(c=>c.start===at&&c.key!=='introduction'&&!c.returned);
  const visual=sceneCuts.some(t=>Math.abs(t-at)<=7)&&!alignedChapters.some(c=>c.returned&&Math.abs(c.start-at)<20);
  const coherentAfter=after.length>=4&&similarity(after.slice(0,Math.ceil(after.length/2)),after.slice(Math.ceil(after.length/2)))>.15;
  const independent=!DEPENDENT.test(row.text)&&terms(row.text).length>=3;
  const shift=before.length>=3&&coherentAfter&&similarity(before,after)<.12;
  // An announced new question may end a worked example, but incidental vocabulary cannot.
  const boundary=prev&&sentenceEnded(prev.text)&&leftEnough&&rightEnough&&
   (chapterChange||shortHeading||(announce&&!(listItem&&enumerating))||(!practice&&independent&&shift&&visual));
  if(boundary)emit();
  current.push(row);
  if(PRACTICE.test(row.text))practice=true;
  if(COMPLETED.test(row.text))practice=false;
 }
 emit();
 // A short closing belongs to its explanation; never drop an unanswered fragment.
 if(groups.length>1&&span(groups.at(-1))<12){groups.at(-2).push(...groups.pop())}
 const proposals=groups.map((rows,i)=>{
  const chapter=alignedChapters.find(c=>rows[0].start>=c.start&&rows[0].start<c.end);
  const segments=tightSpeechPieces(rows).map(p=>({start:Math.max(rows[0].start,p.start),end:Math.min(rows.at(-1).end,p.end)}));
  return {id:'topic-'+(i+1),start:rows[0].start,end:rows.at(-1).end,segments,title:titleFor(rows,chapter),
   chapter:chapter||null,thumbnailTime:rows[0].start+Math.min(6,span(rows)/4),layout:'hybrid',focusX:50,
   status:'needs-review',confidence:'low',method:'general-sentence-discourse',kind:'explanation',
   wordCount:rows.reduce((n,r)=>n+r.text.split(/\s+/u).length,0),
   reviewReasons:['Границы по завершённым предложениям и смене вопроса; проверьте смысловую самостоятельность'],
   boundaryEvidence:{first:rows[0].text,last:rows.at(-1).text,wordAligned:rows.every(r=>r.words?.length),completeEnd:sentenceEnded(rows.at(-1).text)}};
 });
 const clips=assignExclusiveSource(proposals);
 return {clips,candidates:groups.map((rows,i)=>({id:'candidate-'+(i+1),start:rows[0].start,end:rows.at(-1).end,text:rows.map(r=>r.text).join(' ')})),excluded,chapters,
  summary:{...summarizeStoryPlan(clips,duration),completionMode:'general-sentence-discourse',processedUtterances:raw.length,
   keptUtterances:units.length,excludedUtterances:excluded.length,duplicateUtterances:clean.removed.length,
   incompleteTranscript:raw.at(-1).end<duration-5,nonOverlappingSource:true,semanticSubtopicCandidates:groups.length,visualEvidenceSplitCount:0,editorialMerges:0,rejectedFragments:0}};
}
