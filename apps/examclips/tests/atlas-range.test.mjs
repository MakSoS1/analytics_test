import test from 'node:test';
import assert from 'node:assert/strict';
import {findRangeTopics,manualRangeClip,coverageSpans} from '../src/atlas-range.js';

const row=(start,end,text)=>({start,end,text});
const definition='Контейнер представляет собой изолированную среду для приложения и его зависимостей, поэтому запуск остаётся воспроизводимым.';
const example='Например приложение запускается из одного образа на разных серверах. Таким образом зависимости и настройки сохраняются при переносе.';
const lesson=(start=60)=>[row(start,start+25,definition),row(start+26,start+60,example)];
const freeze=value=>{
 if(value&&typeof value==='object'){
  Object.values(value).forEach(freeze);
  Object.freeze(value);
 }
 return value;
};
const overlaps=(a,b)=>a.start<b.end&&a.end>b.start;

test('range discovery keeps absolute source and evidence times',()=>{
 const chunks=[row(0,25,'Проверка микрофона, подождите минуту.'),...lesson()];
 const found=findRangeTopics(chunks,180,{start:55,end:125});
 assert.equal(found.length,1);
 assert.equal(found[0].start,60);
 assert.equal(found[0].end,120);
 assert.equal(found[0].candidate,true);
 assert.equal(found[0].status,'needs-review');
 assert.ok(found[0].screenplay.quality.readyForReview);
 const evidence=found[0].screenplay.summary.flatMap(beat=>beat.evidence);
 assert.ok(evidence.length>=2);
 for(const e of evidence){
  assert.ok(chunks.some(c=>c.start===e.start&&c.end===e.end&&c.text===e.quote));
  assert.ok(e.start>=55&&e.end<=125);
 }
 assert.ok(found[0].segments.every(s=>s.start>=55&&s.end<=125));
});

test('boundary-crossing cues are omitted whole without inventing trimmed speech',()=>{
 const crossingLeft=row(55,75,'Обрезанная левая реплика объясняет другой пример и не должна становиться доказательством.');
 const crossingRight=row(140,170,'Обрезанная правая реплика описывает итог другого алгоритма и не должна становиться доказательством.');
 const chunks=[crossingLeft,...lesson(80),crossingRight];
 const found=findRangeTopics(chunks,200,{start:60,end:150});
 assert.equal(found.length,1);
 assert.equal(found[0].start,80);
 assert.equal(found[0].end,140);
 const quotes=found.flatMap(c=>c.screenplay.beats.map(b=>b.quote));
 assert.ok(!quotes.includes(crossingLeft.text));
 assert.ok(!quotes.includes(crossingRight.text));
 assert.deepEqual(findRangeTopics([crossingLeft,crossingRight],200,{start:60,end:150}),[]);
});

test('discovery does not mutate accepted edits, candidates, transcripts, chapters or EDL order',()=>{
 const chunks=freeze(lesson(60));
 const clips=freeze([{id:'approved-1',start:0,end:160,title:'Ручное название',status:'approved',
  segments:[{start:150,end:160},{start:0,end:30}],
  screenplay:{summary:[{text:'Ручная правка'}]},manualApproval:{checkedAt:'2026-10-20'}}]);
 const chapters=freeze([{start:0,end:180,key:'chapter-1',title:'Изолированное приложение'}]);
 const sceneCuts=freeze([0,90]);
 const before=structuredClone({chunks,clips,chapters,sceneCuts});
 const found=findRangeTopics(chunks,180,{start:55,end:125,clips,chapters,sceneCuts});
 assert.equal(found.length,1);
 assert.deepEqual({chunks,clips,chapters,sceneCuts},before);
 assert.equal(clips[0].status,'approved');
 assert.notEqual(found[0],clips[0]);
});

test('existing noncontiguous source segments block duplicate seconds but leave real gaps discoverable',()=>{
 const chunks=[...lesson(0),...lesson(90),...lesson(180)];
 const clips=[{id:'accepted',start:0,end:240,segments:[{start:180,end:240},{start:0,end:60}]}];
 const found=findRangeTopics(chunks,260,{start:0,end:260,clips});
 assert.equal(found.length,1);
 assert.equal(found[0].start,90);
 assert.equal(found[0].end,150);
 for(const segment of found[0].segments)
  assert.ok(clips[0].segments.every(used=>!overlaps(segment,used)));
});

test('repeating range discovery does not duplicate pending candidates or accepted spans',()=>{
 const chunks=lesson();
 const first=findRangeTopics(chunks,180,{start:55,end:125});
 assert.equal(first.length,1);
 assert.deepEqual(findRangeTopics(chunks,180,{start:55,end:125,clips:first}),[]);
 const accepted=first.map(c=>({...c,candidate:false,status:'approved'}));
 assert.deepEqual(findRangeTopics(chunks,180,{start:55,end:125,clips:accepted}),[]);
 const repeated=findRangeTopics(chunks,180,{start:55,end:125});
 assert.equal(repeated[0].id,first[0].id);
});

test('a cue partly occupied by an existing clip cannot supply its complete quote to a new candidate',()=>{
 const chunks=lesson();
 const found=findRangeTopics(chunks,180,{start:55,end:125,clips:[{id:'taken',start:70,end:80}]});
 assert.deepEqual(found,[],'The only remaining independent cue cannot prove a new lesson');
});

test('padding between nearby cues does not reuse source seconds occupied by another clip',()=>{
 const chunks=lesson();
 const occupied={id:'between',start:85.05,end:85.95};
 const found=findRangeTopics(chunks,180,{start:55,end:125,clips:[occupied]});
 assert.ok(found.every(c=>c.segments.every(s=>!overlaps(s,occupied))));
});

test('empty, invalid and insufficient transcript evidence never fabricates a result',()=>{
 for(const chunks of [[],null,[row(60,90,'Проверка микрофона, подождите минуту.')],
  [row(60,64,'Например вот результат.')],[row(60,90,definition)],
  [row(60,90,'Да.'),row(91,119,'Хорошо.')]])
  assert.deepEqual(findRangeTopics(chunks,180,{start:55,end:125}),[]);
 for(const [start,end,duration] of [[-1,120,180],[125,55,180],[0,181,180],
  [NaN,120,180],[55,Infinity,180],[0,10,0],[0,10,Infinity]])
  assert.deepEqual(findRangeTopics(lesson(),duration,{start,end}),[]);
});

test('the initial source placeholder does not hide discoverable transcript',()=>{
 const found=findRangeTopics(lesson(),180,{start:55,end:125,
  clips:[{id:'draft-1',start:0,end:180}]});
 assert.equal(found.length,1);
});

test('all independently evidenced chapters can become candidates without a count quota',()=>{
 const chapters=Array.from({length:24},(_,i)=>({start:i*70,end:(i+1)*70,
  key:'independent-'+i,title:'Учебная глава '+(i+1)}));
 const chunks=chapters.flatMap(c=>lesson(c.start));
 const found=findRangeTopics(chunks,1680,{start:0,end:1680,chapters});
 assert.equal(found.length,24);
 assert.equal(new Set(found.map(c=>c.id)).size,24);
 const spans=found.flatMap(c=>c.segments).sort((a,b)=>a.start-b.start);
 assert.ok(spans.every((s,i)=>!i||s.start>=spans[i-1].end));
});

test('manual range creates a UUID draft preserving the exact selected interval',()=>{
 const clip=manualRangeClip(60,95,180);
 assert.deepEqual(clip.segments,[{start:60,end:95}]);
 assert.equal(clip.start,60);
 assert.equal(clip.end,95);
 assert.equal(clip.outputSeconds,35);
 assert.equal(clip.candidate,true);
 assert.equal(clip.status,'needs-review');
 assert.ok(clip.reviewReasons.length>0);
 assert.match(clip.id,/^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i);
 assert.notEqual(manualRangeClip(60,95,180).id,clip.id);
 assert.equal(manualRangeClip(0,10,10).outputSeconds,10);
});

test('manual range rejects short, reversed, nonfinite and out-of-source selections',()=>{
 for(const args of [[60,69.999,180],[-1,30,180],[90,60,180],[0,181,180],
  [0,10,0],[0,10,Infinity],[NaN,100,180],[0,Infinity,180]])
  assert.throws(()=>manualRangeClip(...args),RangeError);
});

test('coverage unions accepted EDL source spans instead of counting envelopes or pending candidates',()=>{
 const clips=freeze([
  {id:'accepted',start:20,end:110,segments:[{start:90,end:110},{start:20,end:35}]},
  {id:'overlap',start:30,end:45,status:'needs-review'},
  {id:'pending',start:0,end:120,candidate:true},
  {id:'draft-1',start:0,end:120}
 ]);
 const before=structuredClone(clips);
 assert.deepEqual(coverageSpans(clips,120),{
  included:[{start:20,end:45},{start:90,end:110}],
  gaps:[{start:0,end:20},{start:45,end:90},{start:110,end:120}],
  includedSeconds:45,percent:37.5
 });
 assert.deepEqual(clips,before);
});

test('coverage clamps valid source bounds, joins adjacent spans and ignores invalid segments',()=>{
 assert.deepEqual(coverageSpans([
  {id:'left',segments:[{start:-10,end:20},{start:20,end:40}]},
  {id:'right',segments:[{start:40,end:200},null,{start:NaN,end:20},{start:30,end:10}]}
 ],100),{included:[{start:0,end:100}],gaps:[],includedSeconds:100,percent:100});
 assert.deepEqual(coverageSpans([],100),{included:[],gaps:[{start:0,end:100}],includedSeconds:0,percent:0});
 assert.deepEqual(coverageSpans(null,0),{included:[],gaps:[],includedSeconds:0,percent:0});
 assert.deepEqual(coverageSpans([],Infinity),{included:[],gaps:[],includedSeconds:0,percent:0});
});
