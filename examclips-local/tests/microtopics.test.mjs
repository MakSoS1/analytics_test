import test from 'node:test';import assert from 'node:assert/strict';
import {buildMicrotopics,boundaryQuality,coverageReport} from '../src/microtopics.js';
function lecture(seconds=960,{step=15,topicEvery=180}={}){
 return Array.from({length:Math.ceil(seconds/step)},(_,i)=>{
  const t=i*step,topic=Math.floor(t/topicEvery);
  const firstInTopic=t%topicEvery===0;
  return {start:t,end:Math.min(seconds,t+step),
    text:(firstInTopic?'Теперь рассмотрим новую тему. ':'')+
      ['Это пример процесса Docker и взаимодействия контейнеров.', 'Важен механизм сети и конфигурации интерфейса.',
       'Для проверки можно использовать команды и результаты.'][i%3] };
 });
}
test('does not hallucinate clips without transcript',()=>{assert.deepEqual(buildMicrotopics([],3600),[])});
test('default yields coherent study-size candidates, not 15 second shorts',()=>{
 const clips=buildMicrotopics(lecture(),960);
 assert.ok(clips.length>=3&&clips.length<=15,JSON.stringify(clips.map(x=>x.end-x.start)));
 for(const clip of clips){
  assert.ok(clip.end-clip.start>=60-1.5,JSON.stringify(clip));
  assert.ok(clip.end-clip.start<=300+.01,JSON.stringify(clip));
  assert.equal(clip.status,'needs-review');
  assert.ok(clip.title.includes('тем')||clip.title.length>12);
 }
 assert.equal(clips[0].start,0);assert.ok(clips.at(-1).end>=959);
});
test('five-minute maximum never exceeds bound on normally timed chunks',()=>{
 const clips=buildMicrotopics(lecture(900,{step:20,topicEvery:200}),900,{min:60,target:180,max:300});
 assert.ok(clips.every(c=>c.end-c.start<=300.001));
});
test('topic signal from next sentence is stronger than mid-clause',()=>{
 const a=[{start:0,end:8,text:'И тогда контейнер входит в сеть'},{start:11,end:24,text:'Теперь рассмотрим другую тему.'}];
 const b=[{start:0,end:8,text:'И тогда контейнер входит в сеть'},{start:8,end:24,text:'И потому это выполняется внутри'}];
 assert.ok(boundaryQuality(a,0)>boundaryQuality(b,0));
});
test('short ASR coverage is explicitly review-only, never labeled a finished lesson',()=>{
 const a=buildMicrotopics([{start:100,end:130,text:'И ещё один вопрос'}],3600);
 assert.equal(a.length,1);assert.equal(a[0].confidence,'low');assert.ok(a[0].reviewReasons.length>0);
});
test('full lecture not invented when ASR only covered first minutes',()=>{
 const chunks=lecture(300);
 const result=buildMicrotopics(chunks,3600),report=coverageReport(chunks,3600);
 assert.ok(result.at(-1).end<=301);
 assert.equal(report.partial,true);assert.ok(report.percent<10)
});
test('invalid segmentation configuration rejected',()=>{
 assert.throws(()=>buildMicrotopics(lecture(),960,{min:60,target:200,max:180}));
});
