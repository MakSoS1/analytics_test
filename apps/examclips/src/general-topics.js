/** Local, subject-independent sentence/discourse segmenter. No source identity,
 * topic dictionary, required clip count or fixed lesson duration: a boundary
 * needs spoken or visual evidence; length only arbitrates between evidenced cuts.
 */
import {normalizeChunks} from './segments.js';
import {joinSpeechSentences,sentenceEnded} from './speech-boundaries.js';
import {isEducationalSpeech} from './complete-topics.js';
import {dedupeTranscriptRows} from './topic-editorial-guardrails.js';
import {tightSpeechPieces,summarizeStoryPlan} from './selective-stories.js';
import {opener,closes,invitesQuestions,movesOn,isFiller,reportsQuestion,thanksForQuestion,isRecap,isOpeningHousekeeping} from './discourse-cues.js';
const STOP=new Set(`this that these those they them their there here what which where when why how have has had were was are will would could should shall does did can may might must your our you the and but for with from into then than also just only very really about because therefore example first second third next now okay well let's let us its it's going want know think like make maybe actually right thing things something much many more most some every this one two say said look see get got use used это этой этого этот эти как что чтобы когда который которая которые для или при уже ещё еще также потому поэтому например теперь значит очень будет было были есть вот так мы вы они она оно его их это`.split(/\s+/u));
const terms=text=>(String(text).toLowerCase().match(/[\p{L}\p{N}][\p{L}\p{N}-]{2,}/gu)||[]).filter(t=>!STOP.has(t));
const speech=text=>String(text).replace(/^(?:PROFESSOR|INSTRUCTOR|STUDENT|SPEAKER(?: \d+)?)\s*:\s*/u,'');
// Discourse-level cue used by other modules and tests.
export function announcesTopic(text){
 const t=speech(text);
 if(/(?:look at|consider) (?:this|that|the (?:graph|diagram|same|result|version))|now before[,.]?\s+let me/iu.test(t))return false;
 return opener(t)>=3||/^(?:so[, ]+)?(?:let(?:'s| us) (?:do|work through) (?:an?|the next) example|example \d+|here(?:'s| is) (?:here )?how|рассмотрим (?:следующий )?пример)/iu.test(t);
}
const DEPENDENT=/^\s*(?:because|which|that|this|these|those|it|it's|they|them|therefore|however|but\b|and\b|so\b|потому|поэтому|это\b|этот\b|эта\b|они\b|он\b|она\b|значит\b|следовательно\b)/iu;
const PRACTICE=/(?:let(?:'s| us) do (?:an?|the next) example|example \d+|worked example|let(?:'s| us) solve|solve (?:this|the) (?:problem|exercise)|решим\s+(?:эту\s+)?задачу|разбер[её]м\s+(?:\p{L}+\s+)?(?:пример|задач)|докажем)/iu;
const COMPLETED=/(?:problem solved|that completes|final answer|the result is|задача решена|получили ответ|что и требовалось доказать)/iu;
const span=rows=>rows.length?rows.at(-1).end-rows[0].start:0;
const tidy=s=>String(s).replace(/\s+-(?=\p{L})/gu,'-').replace(/\s+([,.!?;:])/gu,'$1').replace(/\s+/gu,' ').trim();

function phraseAfterCue(sentence){
 let text=speech(sentence).replace(/^\s*(?:(?:okay|ok|oh|well|so|and|now|alright|итак|хорошо)[,.]?\s+)*/iu,'')
  .replace(/^(?:now[, ]+)?(?:let(?:'s| us)\s+)?(?:talk about|speak about|discuss|look at|consider|move (?:on )?to|turn to|go to|start with|tackle|dig into|dive into)\s+/iu,'')
  .replace(/^(?:now\s+)?we(?:'ll| will| are going to|'re(?: going)? to| are to)\s+(?:now\s+)?(?:speak|talk) about\s+/iu,'')
  .replace(/^(?:the )?next one is\s+|^next,?\s+(?:is\s+)?/iu,'')
  .replace(/^(?:and\s+)?finally,?\s+(?:we are arriving at\s+)?/iu,'')
  .replace(/^(?:and\s+)?we (?:also )?have\s+/iu,'')
  .replace(/^(?:теперь\s+)?(?:рассмотрим|поговорим о|обсудим|перейд[её]м к)\s+/iu,'');
 const clarification=text.match(/clarification about (.+?)(?:,| because|$)/iu);
 if(clarification)text=clarification[1];
 // "..., it's called design for failure" / "our third objective is performance" / "... – the error budget"
 const named=text.match(/(?:it'?s|is) called\s+(.+)$/iu)||text.match(/(?:objective|principle|concept|topic)\s+is\s+(.+)$/iu)||text.match(/\s[–—-]\s+(.+)$/u);
 if(named&&named[1].split(/\s+/u).length<=8)text=named[1].replace(/^the\s+/iu,'');
 return text;
}
function titleFor(rows,chapter){
 const first=rows.slice(0,8).map(r=>speech(r.text).trim());
 const cue=opener(first[0])>0;
 let text=cue?phraseAfterCue(first[0]):'';
 // Vague transitions are not useful titles: quote the following actual subject.
 if(!cue||/^(?:the )?(?:next (?:point|part|one)|most powerful technique|other half|truth|problem|on)\b|here (?:is|s) the truth|what came before|^something\b|^let'?s move on|^moving on|^the most\b|^(?:the |our )?(?:first|second|third|next|final) (?:big |design )?(?:objective|principle|question)\b/iu.test(text)||text.split(/\s+/u).length>14){
  const called=first.slice(0,4).map(s=>s.match(/\bis called\s+([^.,;]+)/iu)?.[1]).find(Boolean);
  const named=called||first.slice(1,4).find(s=>/^(?:it'?s|this is|it is called)\s+/iu.test(s))?.replace(/^(?:it'?s|this is|it is called)\s+/iu,'');
  // The sentence after a vague announcement often names it: "Money." / "Why do we mean by high load?"
  const next=first[1]&&(first[1].split(/\s+/u).length<=3||/\?\s*$/u.test(first[1])&&first[1].split(/\s+/u).length<=14)?first[1]:null;
  text=named&&named.split(/\s+/u).length<=10?named:(chapter?.title||next||(cue&&text.split(/\s+/u).length>=2&&text.split(/\s+/u).length<=14?text:null)||first.find(s=>terms(s).length>=3)||first[0]||'Фрагмент лекции');
 }
 const rule=first.find(s=>/^everything about .+ comes down/iu.test(s));
 if(rule)text=rule.replace(/^everything about /iu,'').replace(/ comes down.*$/iu,'');
 text=tidy(text).replace(/[.!?]+$/u,'');
 if(text)text=text[0].toUpperCase()+text.slice(1);
 return text.length<=110?text:text.slice(0,110).replace(/\s+\S*$/u,'')+'…';
}
/** TF-IDF over adjacent content-word pairs of each group. */
function phraseVectors(groups){
 const stem=w=>w.replace(/(?:ing|ed|es|s|ly)$/u,'');
 const grams=groups.map(rows=>{const w=terms(rows.map(r=>r.text).join(' ')).map(stem),m=new Map();
  for(let i=0;i+1<w.length;i++){const g=w[i]+' '+w[i+1];m.set(g,(m.get(g)||0)+1)}return m});
 const df=new Map();for(const g of grams)for(const k of g.keys())df.set(k,(df.get(k)||0)+1);
 return grams.map(g=>{const v=new Map();for(const [k,n] of g){const idf=Math.log(grams.length/df.get(k));if(idf>0)v.set(k,Math.sqrt(n)*idf)}return v});
}
function vectorizer(units){
 const df=new Map();
 for(const u of units)for(const t of new Set(terms(u.text)))df.set(t,(df.get(t)||0)+1);
 const weight=t=>Math.log(1+units.length/(1+(df.get(t)||0)));
 const vector=rows=>{const m=new Map();for(const r of rows)for(const t of terms(r.text))m.set(t,(m.get(t)||0)+1);
  for(const [t,n] of m)m.set(t,Math.sqrt(n)*weight(t));return m};
 const cosine=(x,y)=>{let dot=0,xx=0,yy=0;for(const [t,v] of x){xx+=v*v;dot+=v*(y.get(t)||0)}for(const v of y.values())yy+=v*v;return xx&&yy?dot/Math.sqrt(xx*yy):0};
 return {vector,similarity:(a,b)=>cosine(vector(a),vector(b)),cosine};
}
/** TextTiling depth of lexical cohesion dips at each gap, normalized to ~[0,1]. */
function lexicalDepth(units,similarity,k=6){
 const gaps=units.map((_,i)=>i===0?0:similarity(units.slice(Math.max(0,i-k),i),units.slice(i,i+k)));
 const depth=gaps.map((v,i)=>{
  if(i===0)return 0;
  let l=v,r=v;
  for(let j=i-1;j>=1&&gaps[j]>=l;j--)l=gaps[j];
  for(let j=i+1;j<gaps.length&&gaps[j]>=r;j++)r=gaps[j];
  return (l-v)+(r-v);
 });
 // Uniform speech has no real dips: never inflate noise by a near-zero scale.
 const sorted=depth.slice(1).sort((a,b)=>a-b),p90=sorted[Math.floor(sorted.length*.9)]||1;
 return depth.map(d=>Math.min(1.4,d/Math.max(.12,p90)));
}
/** Split out audience questions and their answers; they are attached to topics later. */
function extractQuestions(sentences,similar=null){
 const content=[],pairs=[];let open=-1e9,pair=null;
 const close=()=>{if(pair)pairs.push(pair);pair=null};
 for(const row of sentences){
  const text=speech(row.text);
  if(invitesQuestions(text)){close();open=row.end;row.role='invite';continue}
  const cue=opener(text);
  if(pair&&cue>=3&&!reportsQuestion(text)){close();open=-1e9}
  const inQa=row.start-open<=75;
  const asks=reportsQuestion(text)||(inQa&&/\?\s*$/u.test(text)&&!pair?.question);
  const newSubject=pair&&span(pair.rows)>=20&&similar&&similar(pair.rows,[row])<.08;
  if(asks&&(!pair||reportsQuestion(text)&&pair.rows.length>1||/\?\s*$/u.test(text)&&newSubject)){
   close();pair={rows:[row],question:/\?\s*$/u.test(text)?row:null};open=row.end;continue;
  }
  if(pair){
   pair.rows.push(row);if(!pair.question&&/\?\s*$/u.test(text))pair.question=row;
   open=row.end;
   if(thanksForQuestion(text))close();
   continue;
  }
  if(inQa&&cue<3&&!isFiller(text)&&row.start-open<=20){pair={rows:[row],question:null,implicit:true};open=row.end;continue}
  content.push(row);
 }
 close();
 const real=[];
 for(const p of pairs){
  const audience=p.rows.some(r=>reportsQuestion(r.text)||thanksForQuestion(r.text));
  if(audience||span(p.rows)<=(p.implicit?60:100)){real.push(p);continue}
  // Chat replies can precede a rhetorical question that opens the next topic: keep only that head.
  const resume=p.rows.findIndex((r,k)=>k>0&&(/\?\s*$/u.test(speech(r.text))||opener(speech(r.text))>=2.6));
  if(p.implicit&&resume>0&&span(p.rows.slice(0,resume))<=60){real.push({...p,rows:p.rows.slice(0,resume)});content.push(...p.rows.slice(resume))}
  else content.push(...p.rows);
 }
 content.sort((a,b)=>a.start-b.start);
 return {content,pairs:real};
}
/** Union-free exclusive ownership: no source second appears in two videos. */
function claimExclusive(clips){
 const claimed=[];
 const subtract=(part)=>{
  let pieces=[{...part}];
  for(const c of claimed)pieces=pieces.flatMap(p=>{
   if(c.end<=p.start||c.start>=p.end)return [p];
   const out=[];if(c.start>p.start)out.push({start:p.start,end:c.start});if(c.end<p.end)out.push({start:c.end,end:p.end});return out;
  });
  return pieces.filter(p=>p.end-p.start>=.08);
 };
 const output=[];
 for(const clip of clips){
  const spans=[];
  for(const part of clip.segments.slice().sort((a,b)=>a.start-b.start))
   for(const p of subtract(part)){
    if(spans.length&&p.start-spans.at(-1).end<=.06)spans.at(-1).end=Math.max(spans.at(-1).end,p.end);else spans.push(p);
    claimed.push(p);
   }
  if(!spans.length)continue;
  output.push({...clip,start:spans[0].start,end:spans.at(-1).end,segments:spans,
   outputSeconds:+spans.reduce((n,x)=>n+x.end-x.start,0).toFixed(2)});
 }
 return output;
}
function lengthValue(seconds,protectedPractice,shortLimit=75){
 if(seconds<20)return -10;
 if(seconds<shortLimit)return -Math.pow((shortLimit-seconds)/12,2);
 if(seconds<=420||protectedPractice)return 0;
 return -Math.pow((seconds-420)/120,2);
}

export function planGeneralTopics(chunks,duration,{sceneCuts=[],chapters=[]}={}){
 const raw=normalizeChunks(chunks,duration);
 if(!raw.length)return {clips:[],candidates:[],excluded:[],summary:summarizeStoryPlan([],duration)};
 const clean=dedupeTranscriptRows(raw),sentences=joinSpeechSentences(clean.rows);
 const excluded=[...clean.removed];
 const drop=(row,reason)=>excluded.push({...row,reason});
 // The opening ends at the first announced topic after the plan, or the first slide chapter.
 const introChapter=chapters.find(c=>c.key==='introduction');
 const firstTopicChapter=chapters.filter(c=>c.key!=='introduction').sort((a,b)=>a.start-b.start)[0];
 const openingEnd=Math.min(firstTopicChapter?.start??Infinity,introChapter?.end??Infinity,
  Math.max(150,Math.min(360,duration*.08)));
 const kept=[];
 for(const row of sentences){
  const text=speech(row.text);
  const publisher=row.start<60&&/following content is provided|support.*(?:open.?courseware|donation)|make a donation|visit mit opencourseware|creative commons license/iu.test(text);
  if(publisher||!isEducationalSpeech(text))drop(row,'Организационная речь или пустая реплика');
  else if(row.start<openingEnd&&isOpeningHousekeeping(text))drop(row,'Приветствие, биография или план лекции');
  else if(isFiller(text))drop(row,'Обращение к чату, перерыв или переход без содержания');
  else kept.push(row);
 }
 const lastHousekeeping=Math.max(-Infinity,...excluded.filter(r=>r.reason==='Приветствие, биография или план лекции').map(r=>r.start));
 for(let i=kept.length-1;i>=0;i--)if(kept[i].start<lastHousekeeping){drop(kept[i],'Вступление до начала первой темы');kept.splice(i,1)}
 while(Number.isFinite(lastHousekeeping)&&kept.length&&kept[0].start<openingEnd&&kept[0].start-lastHousekeeping<12&&opener(speech(kept[0].text))<2.6){
  drop(kept.shift(),'Вступление до начала первой темы');
 }
 const {content:withInvites,pairs}=extractQuestions(kept,vectorizer(kept).similarity);
 const units=[];
 for(const row of withInvites)units.push(row);
 for(const row of kept)if(row.role==='invite')drop(row,'Приглашение задать вопрос');
 if(!units.length&&!pairs.length)return {clips:[],candidates:[],excluded,chapters,summary:summarizeStoryPlan([],duration)};
 const all=[...units,...pairs.flatMap(p=>p.rows)];
 const {vector,similarity,cosine}=vectorizer(all.length?all:units);
 // Slide chapters snap to the spoken sentence that introduces their heading.
 const titleTerms=t=>new Set(terms(t));
 const chapterAt=new Map();
 for(const ch of chapters){
  if(ch.key==='introduction')continue;
  const returned=chapters.some(prior=>prior!==ch&&prior.start<ch.start&&
   [...titleTerms(prior.title)].join(' ')===[...titleTerms(ch.title)].join(' '));
  if(returned)continue;
  const root=t=>t.slice(0,5),wanted=new Set([...titleTerms(ch.title)].map(root));let best=-1,bestScore=-Infinity;
  units.forEach((u,i)=>{
   // Sampled slide changes lag the spoken announcement: search mostly before.
   const dt=u.start-ch.start;if(dt<-35||dt>10)return;
   const heard=[u,units[i+1]].filter(Boolean).flatMap(r=>terms(r.text)).filter(t=>wanted.has(root(t))).length;
   // List items ("First, scaling up") are inside a topic; questions often open one.
   const cue=opener(u.text)>=2?opener(u.text):/\?\s*$/u.test(u.text)?1.5:0;
   const score=cue*1.5+heard*.6-Math.abs(dt)/(dt>0?12:30)-(DEPENDENT.test(speech(u.text))?2:0);
   if(score>bestScore){bestScore=score;best=i}
  });
  if(best>0)chapterAt.set(best,ch);
 }
 const depth=lexicalDepth(units,similarity);
 // Practice spans: a worked solution is not cut by vocabulary or length.
 // It ends at its stated result or where the lecturer explicitly opens the next topic.
 const inPractice=[];let practice=false;
 for(const u of units){
  if(practice&&opener(speech(u.text))>=2.6&&!PRACTICE.test(u.text))practice=false;
  if(PRACTICE.test(u.text))practice=true;
  inPractice.push(practice);if(COMPLETED.test(u.text))practice=false;
 }
 // Items of an announced list ("three reasons", "five states") stay in one lesson.
 const LIST=/\b(?:two|three|four|five|six|seven|several|few)\s+(?:\p{L}+\s+)?(?:reasons|rules|states|options|ways|types|kinds|drivers|metrics|steps|stages|signals|problems|things|objectives|principles|acronyms|methods|layers|instructions|tools|components|parts|pillars|properties|concepts|questions)\b|(?:два|три|четыре|пять|несколько)\s+\p{L}+/iu;
 // Short announcements ("Two reasons.") are dropped as content but still announce the list.
 const lists=sentences.filter(r=>LIST.test(r.text)).map(r=>r.start);
 const listUntil=units.map(u=>lists.filter(t=>t<=u.start&&u.start-t<=150).at(-1)??-Infinity);
 const pausedBefore=new Set();
 for(let i=1;i<units.length;i++){
  const gapRows=[...excluded,...pairs.flatMap(p=>p.rows)].filter(r=>r.start>=units[i-1].end-.01&&r.end<=units[i].start+.01);
  if(gapRows.some(r=>invitesQuestions(r.text)||movesOn(r.text)||r.role==='invite'||pairs.some(p=>p.rows.includes(r))))pausedBefore.add(i);
 }
 const score=units.map((u,i)=>{
  if(i===0)return 0;
  const prev=units[i-1],text=speech(u.text);
  if(!sentenceEnded(prev.text))return -Infinity;
  let cue=opener(text);
  // "Why would you want this? Performance." answers a question; it is not a heading.
  if(cue<3&&/\?\s*$/u.test(prev.text))cue=0;
  const listed=Number.isFinite(listUntil[i])&&cue<3;
  if(listed)cue=0;
  // Vocabulary alone is weak evidence; an announced transition is strong.
  let s=cue+depth[i]*(listed?.8:1.5);
  if(pausedBefore.has(i))s+=2;
  if(closes(speech(prev.text)))s+=1;
  // The lecture-wide recap is a lesson of its own, not the end of the last topic.
  if(isRecap(text))s+=2.5;
  if(chapterAt.has(i))s+=2.5;
  if(sceneCuts.some(t=>Math.abs(t-u.start)<=7))s+=.5;
  if(closes(text)&&!isRecap(text))s-=4;
  if(DEPENDENT.test(text)&&cue<2&&!pausedBefore.has(i))s-=2.5;
  if(cue===0&&!chapterAt.has(i)&&!pausedBefore.has(i)&&(depth[i]<.9||terms(text).length<3))return -Infinity;
  if(inPractice[i]&&inPractice[i-1]&&cue<3&&!chapterAt.has(i))return -Infinity;
  // Evidence is required; a cut never follows from duration alone.
  return s>=1.2?s:-Infinity;
 });
 // Dynamic programming over evidenced boundaries with a soft length preference.
 const THRESHOLD=2.4,n=units.length,best=new Array(n+1).fill(-Infinity),from=new Array(n+1).fill(0);
 // A long worked solution is exempt from the length preference, nothing else.
 const practiceSeconds=units.map(u=>0);
 units.forEach((u,i)=>{practiceSeconds[i]=(i?practiceSeconds[i-1]:0)+(inPractice[i]?u.end-u.start:0)});
 const shortLimit=duration>=600?75:30;
 best[0]=0;
 for(let j=1;j<=n;j++){
  for(let i=j-1;i>=0;i--){
   const spoken=units[j-1].end-units[i].start,drill=practiceSeconds[j-1]-(i?practiceSeconds[i-1]:0);
   const hasPractice=drill>=spoken*.6;
   if(i>0&&score[i]===-Infinity)continue;
   if(best[i]===-Infinity)continue;
   const value=best[i]+(i>0?score[i]-THRESHOLD:0)+lengthValue(spoken,hasPractice,shortLimit);
   if(value>best[j]){best[j]=value;from[j]=i}
  }
 }
 const cuts=[];for(let j=n;j>0;j=from[j])cuts.unshift(from[j]);
 let groups=cuts.map((start,k)=>units.slice(start,cuts[k+1]??n)).filter(g=>g.length);
 // An opening remnant that is neither announced nor substantial is part of the introduction.
 if(groups.length>1&&groups[0][0].start<openingEnd&&span(groups[0])<60&&opener(groups[0][0].text)<3){
  for(const r of groups.shift())drop(r,'Короткое вступление без самостоятельной темы');
 }
 const topics=groups.map(rows=>({rows,extra:[],notes:[],recap:rows.some(r=>isRecap(r.text))}));
 // The same concept explained twice becomes one lesson assembled from both places.
 // Shared single words are common across a lecture; shared phrases ("scale out",
 // "single point of failure") identify a repeated explanation.
 const phrases=phraseVectors(topics.map(t=>t.rows));
 for(let j=topics.length-1;j>0;j--){
  const b=topics[j];if(b.recap)continue;
  const ranked=topics.map((a,i)=>({i,sim:i<j-1&&!a.recap?cosine(phrases[i],phrases[j]):0})).sort((x,y)=>y.sim-x.sim);
  const [first,second]=ranked,a=topics[first.i];
  const total=span(a.rows)+span(b.rows)+a.extra.reduce((n,x)=>n+span(x),0);
  // A repetition also restates the earlier lesson in its opening sentences.
  const restates=similarity(b.rows.slice(0,4),a.rows)>=.12;
  if(first.sim>=.03&&first.sim>=(second?.sim||0)*1.8&&restates&&total<=480){
   a.extra.push(b.rows);a.notes.push('Тема объясняется ещё раз позже — фрагменты собраны в один ролик');
   topics.splice(j,1);phrases.splice(j,1);
  }
 }
 // Each audience question joins the lesson it is about; otherwise it stands alone if substantive.
 const standalone=[];
 for(const pair of pairs){
  const v=vector(pair.rows);
  const sims=topics.map(t=>cosine(v,vector([...t.rows,...t.extra.flat()])));
  const order=sims.map((s,i)=>[s,i]).sort((a,b)=>b[0]-a[0]);
  const words=terms(pair.rows.map(r=>r.text).join(' ')).length;
  if(order[0]&&order[0][0]>=.1&&(order[0][0]>=(order[1]?.[0]||0)*1.05||Math.abs(order[0][1]-order[1][1])===1)&&words>=10){
   topics[order[0][1]].extra.push(pair.rows);topics[order[0][1]].notes.push('Добавлен ответ на вопрос слушателя');
  }else if(span(pair.rows)>=40&&words>=25)standalone.push({rows:pair.rows,extra:[],notes:['Ответ на вопрос слушателя'],question:pair.question});
  else for(const r of pair.rows)drop(r,'Короткий вопрос из чата без самостоятельного объяснения');
 }
 const proposals=[...topics,...standalone].sort((a,b)=>a.rows[0].start-b.rows[0].start).map((t,i)=>{
  // Only a slide chapter that was snapped to this lesson's first sentence may name it.
  const rows=t.rows,chapter=chapterAt.get(units.indexOf(rows[0]))||null;
  const parts=[rows,...t.extra].map(part=>tightSpeechPieces(part).map(p=>({start:Math.max(part[0].start,p.start),end:Math.min(part.at(-1).end,p.end)})));
  const segments=parts.flat();
  const announced=opener(rows[0].text)>=2;
  const reasons=[announced?'Начинается с объявления темы; проверьте полноту объяснения':
   'Начало без явного объявления темы — проверьте, понятен ли вход',...t.notes];
  const question=t.question?tidy(speech(t.question.text)).replace(/[?]+$/u,''):'';
  return {id:'topic-'+(i+1),start:segments[0].start,end:Math.max(...segments.map(s=>s.end)),segments,
   title:question?'Вопрос: '+(question.length>90?question.slice(0,90).replace(/\s+\S*$/u,'')+'…':question):titleFor(rows,chapter),
   chapter:chapter||null,thumbnailTime:rows[0].start+Math.min(6,span(rows)/4),layout:'hybrid',focusX:50,
   status:'needs-review',confidence:announced&&sentenceEnded(rows.at(-1).text)?'medium':'low',
   method:'general-sentence-discourse',kind:t.question?'question':'explanation',
   assembled:t.extra.length>0,
   wordCount:[rows,...t.extra].flat().reduce((n,r)=>n+r.text.split(/\s+/u).length,0),
   reviewReasons:reasons,
   boundaryEvidence:{first:rows[0].text,last:(t.extra.at(-1)||rows).at(-1).text,wordAligned:rows.every(r=>r.words?.length),
    completeEnd:sentenceEnded(rows.at(-1).text),announced}};
 });
 const clips=claimExclusive(proposals);
 return {clips,candidates:groups.map((rows,i)=>({id:'candidate-'+(i+1),start:rows[0].start,end:rows.at(-1).end,text:rows.map(r=>r.text).join(' ')})),excluded,chapters,
  summary:{...summarizeStoryPlan(clips,duration),completionMode:'general-sentence-discourse',processedUtterances:raw.length,
   keptUtterances:units.length+pairs.reduce((n,p)=>n+p.rows.length,0),excludedUtterances:excluded.length,duplicateUtterances:clean.removed.length,
   incompleteTranscript:raw.at(-1).end<duration-5,nonOverlappingSource:true,semanticSubtopicCandidates:groups.length,
   visualEvidenceSplitCount:chapterAt.size,editorialMerges:proposals.filter(p=>p.assembled).length,rejectedFragments:0,
   audienceQuestions:pairs.length}};
}
