import {splitTranscriptForStory} from './selective-stories.js';
/**
 * Educational term-recall quiz (MVP, extractive only).
 * The correct answer is copied from the local transcript; no generative facts.
 * These are NOT validated concept-comprehension questions.
 */
const common=new Set(('который которая которые значит просто теперь далее потому также когда может нужно будет если только после через чтобы такое тогда этот этого очень давайте дальше снова здесь пока вообще например имеется часто конечно пока то есть является является of when this these those then since should being from into about while using with would could first next there their have what that where which your into then there').split(/\s+/));
const words=(text='')=>String(text).match(/[\p{L}][\p{L}\p{N}-]{4,}/gu)||[];
const clean=s=>String(s).toLowerCase().normalize('NFC');
export function quizForClip(clip,chunks,{count=5}={}){
 if(!clip||!Array.isArray(chunks))return [];
 const text=splitTranscriptForStory(chunks,clip).map(x=>x.text).join(' ').replace(/\s+/g,' ');
 if(text.length<110)return [];
 const sentences=text.split(/(?<=[.!?…])\s+/u).map(x=>x.trim()).filter(s=>s.length>=36&&s.length<=245);
 const vocabulary=[...new Set(words(text).map(clean))]
  .filter(w=>!common.has(w)&&w.length>=5&&w.length<=22);
 if(vocabulary.length<5)return [];
 const output=[],used=new Set();
 for(const sentence of sentences){
  const available=words(sentence)
    .filter(w=>w.length>=5&&w.length<=22&&!common.has(clean(w))&&!used.has(clean(w)));
  if(!available.length)continue;
  available.sort((a,b)=>b.length-a.length||a.localeCompare(b,'ru'));
  const answer=available[0],answerKey=clean(answer);
  const distractors=vocabulary.filter(w=>w!==answerKey&&!sentence.toLowerCase().includes(w))
    .sort((a,b)=>Math.abs(a.length-answer.length)-Math.abs(b.length-answer.length)||a.localeCompare(b,'ru'))
    .slice(0,3);
  if(distractors.length<3)continue;
  const start=sentence.indexOf(answer);
  if(start<0)continue;
  const question=sentence.slice(0,start)+'_____ '+sentence.slice(start+answer.length);
  const options=[...distractors,answer];
  // Stable, balanced order; no random values or hidden answer leaks.
  const rotation=output.length%4;
  const sorted=options.slice(rotation).concat(options.slice(0,rotation));
  output.push({
    id:'q-'+(output.length+1),type:'term-recall',
    prompt:'Какое слово было в объяснении преподавателя?',
    quote:question.slice(0,245),
    options:sorted,
    correctIndex:sorted.findIndex(w=>w===answer),
    evidence:sentence,reference:answer
  });
  used.add(answerKey);
  if(output.length>=count)break;
 }
 return output;
}
export function gradeQuiz(questions,answers){
 if(!Array.isArray(questions)||!Array.isArray(answers))throw Error('Invalid quiz');
 let correct=0,answered=0;
 questions.forEach((q,i)=>{
  if(Number.isInteger(answers[i])&&answers[i]>=0&&answers[i]<q.options.length){
    answered++;if(answers[i]===q.correctIndex)correct++;
  }
 });
 return {correct,answered,total:questions.length,percent:questions.length?Math.round(100*correct/questions.length):0};
}
export function toQuizJson(clip,questions){
 return {schema:1,title:clip.title,start:clip.start,end:clip.end,
  disclaimer:'Extractive term recall questions. Not an independently validated educational exam.',
  questions:questions.map(q=>({...q}))};
}
