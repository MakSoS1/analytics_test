import test from 'node:test';import assert from 'node:assert/strict';
import {planSelectiveStories,sourceSegments,storyDuration,summarizeStoryPlan,findLectureCandidates,
selectValuableCandidates,tightSpeechPieces} from '../src/selective-stories.js';
const chunk=(start,end,text)=>({start,end,text});
const informative='Docker контейнеры позволяют изолировать приложения потому что процессы используют общее ядро системы. Например зависимости программы остаются внутри образа.';
const more='Docker контейнер использует образ для повторяемого запуска и изоляции процессов. Это позволяет независимо обновлять сервисы и конфигурацию.';
test('selects minority of an hour instead of trying to carve whole lecture',()=>{
 const chunks=[
  chunk(10,45,informative),chunk(55,85,'Организационный момент проверка микрофона, подождите минуту, начнём чуть позже.'),
  chunk(145,179,more),chunk(700,745,'Теперь рассмотрим сетевые сервисы. Например балансировщик распределяет запросы между несколькими экземплярами приложения.'),
  chunk(800,835,'Подождите минуту, перерыв на чай и проверка микрофона.'),
  chunk(1100,1138,'Таким образом контейнеры помогают доставлять приложения повторяемо, потому что образы хранят зависимости.')
 ];
 const p=planSelectiveStories(chunks,3600,{keepFraction:.2,min:20,target:100,max:160});
 assert.ok(p.clips.length>0);assert.ok(p.summary.keptPercent<20);
 assert.ok(p.clips.every(c=>c.status==='needs-review'));
 assert.ok(!p.clips.flatMap(c=>c.segments).some(s=>s.start===55||s.start===800));
 assert.ok(p.summary.discardedSeconds>3000);
});
test('nonconsecutive text from one microtopic can form a multi-segment story',()=>{
 const rows=[
  chunk(10,47,informative),chunk(90,120,'Теперь перейдём к оплате отпусков и рассмотрим бухгалтерские начисления на практике.'),
  chunk(380,421,more)
 ];
 const p=planSelectiveStories(rows,700,{min:25,target:100,max:145,keepFraction:.6});
 assert.ok(p.clips.some(c=>sourceSegments(c).length>=2),JSON.stringify(p.clips));
 const joint=p.clips.find(c=>c.segments.length>1);
 assert.equal(storyDuration(joint),joint.segments.reduce((x,c)=>x+c.end-c.start,0));
});
test('empty or mostly filler source produces no fabricated video',()=>{
 const p=planSelectiveStories([chunk(5,22,'Проверка микрофона и организационный момент, давайте подождём немного.'),
  chunk(50,66,'Окей, да да да, слышно меня?')],120);
 assert.equal(p.clips.length,0);
});
test('budget and overlapping intervals are consistently bounded',()=>{
 const c=[
  {id:'a',start:0,end:45,seconds:45,score:5},
  {id:'b',start:30,end:90,seconds:60,score:4},
  {id:'c',start:120,end:160,seconds:40,score:3}
 ];
 const chosen=selectValuableCandidates(c,200,{keepFraction:.25});
 assert.equal(chosen.length,1);assert.equal(chosen[0].id,'a');
 const summary=summarizeStoryPlan([{segments:[{start:0,end:50},{start:40,end:80}]}],200);
 assert.equal(summary.keptSeconds,80);assert.equal(summary.keptPercent,40);
});
test('no text creates no clips',()=>assert.deepEqual(planSelectiveStories([],3600).clips,[]));

test('observed gaps over 1.15s are removed within one educational explanation',()=>{
 const pieces=tightSpeechPieces([
  chunk(0,6,'Docker важен'),
  chunk(7.6,13,'Потому что сохраняет зависимости'),
  chunk(13.2,20,'Таким образом запуск повторяем')
 ]);
 assert.equal(pieces.length,2);
 assert.ok(pieces[0].end<=6.2);
 assert.ok(pieces[1].end>=20);
});
test('normal short breathing pauses are preserved instead of jump-cutting every word',()=>{
 const pieces=tightSpeechPieces([chunk(1,2,'Контейнер'),chunk(2.6,3.4,'образ'),chunk(4.1,5,'сборка')]);
 assert.equal(pieces.length,1);
});
