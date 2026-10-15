/**
 * Extractive local microtopic proposer for educational speech.
 * Does not claim any LLM understanding or certify self-contained lessons.
 * The end-user reviews uncertain starts/ends and titles before publishing.
 */
import {normalizeChunks,titleFromText} from './segments.js';
const clamp=(x,a,b)=>Math.max(a,Math.min(b,x));
const TOPIC_CUE=/^(?:а теперь|теперь|далее|дальше|следующ|перейд[её]м|переходим|рассмотрим|разбер[её]м|поговорим|начн[её]м|итак|давайте рассмотрим|таким образом|next|now (?:let'?s|we)|moving on|first of all|let'?s (?:look|discuss|talk)|finally|in summary)/iu;
const CONCLUSION=/(?:таким образом|подвед[её]м итог|получается|итого|в результате|что и требовалось|in summary|to sum up|in conclusion|this means)[.!?…]*$/iu;
const STOPS=new Set('и в на не что как это то он она они мы вы я для но при или из от по до а же уже когда где если then this that with from into have were there them the and for are but now next our вот просто значит значит да ну соответственно также здесь такой также можно будет типа такой потому эти этот'.split(' '));
function tokens(text=''){
 return (text.toLowerCase().match(/[\p{L}\p{N}]{4,}/gu)||[]).filter(w=>!STOPS.has(w));
}
function distance(left,right){
 const a=new Set(tokens(left)),b=new Set(tokens(right));
 if(a.size<3||b.size<3)return 0.35;
 let overlap=0;for(const x of a)if(b.has(x))overlap++;
 return clamp(1-overlap/(a.size+b.size-overlap),0,1);
}
function extractTitle(rows,index){
 // Prefer a content-bearing sentence over "now let's move to another topic".
 // Strictly extract text from the transcript, never generate imaginary explanations.
 const picked=rows.slice(index,index+7).map(c=>c.text).join(' ').replace(/\s+/g,' ').trim();
 const sentences=picked.split(/(?<=[.!?…])\s+/u).map(x=>x.trim()).filter(Boolean);
 const generic=/^(?:теперь|далее|давайте|перейд[её]м|следующ|ну|вот|и вот|как вы видите|so now|moving on|let us|let's)/iu;
 const ranked=sentences.map((sentence,k)=>{
   const words=tokens(sentence);
   const specific=new Set(words.filter(word=>word.length>=5));
   const score=specific.size*1.5+(words.length>=4?2:0)-(generic.test(sentence)?3.8:0)-k*.32;
   return {sentence,score};
 }).sort((x,y)=>y.score-x.score);
 const candidate=ranked[0]?.sentence||picked;
 return titleFromText(candidate.slice(0,145))||'Микротема: требуется заголовок';
}
export function boundaryQuality(rows,index){
 if(index<0||index>=rows.length-1)return 0;
 const last=rows[index],next=rows[index+1];
 const pause=clamp(next.start-last.end,0,7);
 const before=rows.slice(Math.max(0,index-5),index+1).map(c=>c.text).join(' ');
 const after=rows.slice(index+1,index+7).map(c=>c.text).join(' ');
 const novelty=distance(before,after);
 let score=Math.min(2.4,pause*.75) + (/[.!?…]\s*$/u.test(last.text)?0.8:0) +
    (TOPIC_CUE.test(next.text.trim())?2.3:0) +
    (CONCLUSION.test(last.text.trim())?1.8:0) + 1.3*novelty;
 // Avoid cutting immediately before a fragment clearly continuing a sentence.
 if(/^(?:и|но|а|потому что|который|которая|то есть|and|but|because)\b/iu.test(next.text.trim()))score-=2;
 return score;
}
function scoreDuration(seconds,{min,target,max}){
 if(seconds<min)return -4-7*(min-seconds)/min;
 if(seconds>max)return -Infinity;
 const relative=Math.abs(seconds-target)/target;
 return 1.3-3*relative-(seconds>180?(seconds-180)/120*.9:0);
}
function hasCompleteStart(text){
 return !/^(?:и|а|но|также|здесь|то есть|ну|так вот|потому что|and|but|because|which)\b/iu.test(text.trim());
}
function reasonFor(rows,i,j,quality,forced=false){
 const first=rows[i],last=rows[j],reasons=[];
 if(!hasCompleteStart(first.text))reasons.push('Начало может требовать предыдущего контекста');
 if(!/[.!?…]\s*$/u.test(last.text))reasons.push('Конец может обрывать предложение');
 if(quality<1.5&&!forced)reasons.push('Слабый сигнал завершения темы');
 if(forced)reasons.push('Граница подобрана по ограничению длительности');
 const words=rows.slice(i,j+1).reduce((n,c)=>n+tokens(c.text).length,0);
 if(words<30)reasons.push('Слишком мало распознанной речи');
 return reasons;
}
export function buildMicrotopics(chunks,duration,{min=60,target=160,max=300}={}){
 if(!Number.isFinite(duration)||duration<=0) return [];
 if(!(min>=30&&target>=min&&max>=target&&max<=600))throw Error('Invalid microtopic length parameters');
 const rows=normalizeChunks(chunks,duration).filter(c=>c.text.length>1);
 if(!rows.length)return [];
 const start=Math.max(0,rows[0].start-1.5),end=Math.min(duration,rows.at(-1).end+.6);
 if(end-start<min){
   const reasons=['Для законченной микротемы слишком мало распознанной речи'];
   return [{id:'microtopic-1',start,end,title:extractTitle(rows,0),layout:'hybrid',focusX:50,
      confidence:'low',reviewReasons:reasons,status:'needs-review',method:'extractive',transcriptRange:[0,rows.length-1]}];
 }
 // Candidate cuts are sentence/pause boundaries only; never insert a cut *inside* an ASR chunk.
 const n=rows.length,candidateTimes=[start,...rows.map(r=>r.end)],quality=rows.map((r,i)=>boundaryQuality(rows,i));
 const best=new Array(n+1).fill(-Infinity),parent=new Array(n+1).fill(-1);
 best[0]=0;
 for(let j=1;j<=n;j++){
   const stop=j===n?end:Math.min(duration,rows[j-1].end);
   // Optimize the complete segmentation rather than splitting every fixed N seconds.
   for(let i=j-1;i>=0;i--){
     const begin=i===0?start:rows[i].start;
     const length=stop-begin;
     if(length>max+3)break;
     const lengthScore=scoreDuration(length,{min,target,max});
     if(!Number.isFinite(lengthScore)||!Number.isFinite(best[i]))continue;
     const q=j===n?2:quality[j-1];
     // Penalize many clips, favour a coherent, less fragmented study session.
     const candidate=best[i]+lengthScore+q*.85-1.3;
     if(candidate>best[j]){best[j]=candidate;parent[j]=i}
   }
 }
 if(!Number.isFinite(best[n])){
   // Extremely long ASR blocks / missing timings: ask to review instead of claiming topic completeness.
   const out=[];
   for(let i=0;i<n;){
     let j=i;
     while(j+1<n&&rows[j+1].end-rows[i].start<=max)j++;
     const until=Math.min(duration,rows[j].end);
     if(until<=rows[i].start)break;
     out.push({id:'microtopic-'+(out.length+1),start:rows[i].start,end:until,
       title:extractTitle(rows,i),layout:'hybrid',focusX:50,confidence:'low',status:'needs-review',
       reviewReasons:['ASR-таймкоды или структура речи не позволили найти надёжную границу'],
       transcriptRange:[i,j],method:'extractive'});
     i=j+1;
   }
   return out;
 }
 const intervals=[];for(let j=n;j>0;){const i=parent[j];if(i<0)break;intervals.unshift([i,j]);j=i}
 return intervals.map(([i,j],k)=>{
   const a=i===0?start:rows[i].start,b=j===n?end:rows[j-1].end,localScore=j===n?2:quality[j-1];
   const reasons=reasonFor(rows,i,j-1,localScore);
   if(b-a<min-1)reasons.push('Отрезок короче рекомендуемой 1 минуты');
   const confident=reasons.length===0&&localScore>=2.1;
   return {id:'microtopic-'+(k+1),start:a,end:b,title:extractTitle(rows,i),layout:'hybrid',focusX:50,
     confidence:confident?'medium':'low',status:'needs-review',
     reviewReasons:reasons.length?reasons:['Проверьте, раскрыта ли микротема целиком'],
     transcriptRange:[i,j-1],method:'extractive'};
 });
}
export function coverageReport(chunks,duration){
 const rows=normalizeChunks(chunks,duration);
 if(!rows.length)return {recognizedSeconds:0,percent:0,partial:true};
 const recognizedSeconds=rows.at(-1).end-rows[0].start;
 return {recognizedSeconds,percent:Math.round(100*recognizedSeconds/duration),partial:rows.at(-1).end<duration-5};
}
