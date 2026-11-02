import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeChunks} from '../src/segments.js';
import {joinSpeechSentences} from '../src/speech-boundaries.js';
import {planGeneralTopics as planCompleteTopics} from '../src/general-topics.js';

test('normalization preserves measured word timestamps',()=>{
 const words=[{text:'Hello.',start:1,end:2}];
 assert.deepEqual(normalizeChunks([{start:1,end:2,text:'Hello.',words}],3)[0].words,words);
});
test('sentence can continue past 45 seconds without starting the next clip mid-thought',()=>{
 const units=joinSpeechSentences([{start:0,end:44,text:'The explanation continues with the most'},{start:44,end:52,text:'important consequence.'}]);
 assert.equal(units.length,1);assert.equal(units[0].end,52);
});
test('measured words separate transition from preceding sentence, never interpolate a cut',()=>{
 const words=[{text:'Conclusion.',start:0,end:2},{text:'Now',start:2.4,end:3},{text:'consider',start:3,end:3.6},{text:'probability.',start:3.6,end:5}];
 const units=joinSpeechSentences([{start:0,end:5,text:'Conclusion. Now consider probability.',words}]);
 assert.equal(units.length,2);assert.equal(units[1].start,2.4);assert.equal(units[0].end,2);
});
for(const [first,second] of [['photosynthesis','cellular respiration'],['compound interest','inflation'],['linear functions','quadratic equations']]){
 test(`topic boundaries are independent of Docker vocabulary: ${first}`,()=>{
  const rows=[{start:0,end:20,text:`Today we explain ${first}. This process has several important properties.`},
   {start:20,end:40,text:`For example ${first} behaves consistently under these conditions.`},
   {start:40,end:60,text:`That completes the explanation of ${first}.`},
   {start:60,end:78,text:`Now let us discuss ${second}.`},
   {start:78,end:100,text:`For example ${second} follows a different mechanism and has observable consequences.`},
   {start:100,end:125,text:`This explains why ${second} matters in practice.`}];
  const p=planCompleteTopics(rows,125);
  assert.equal(p.clips.length,2);assert.equal(p.clips[1].start,60);
  assert.ok(p.clips[1].title.toLowerCase().includes(second));
 });
}

test('unpunctuated SRT is kept intact rather than guessing a cut inside a phrase',()=>{
 const p=planCompleteTopics([{start:0,end:42,text:'We explain energy conservation and continue with the most'},
  {start:42,end:67,text:'important consequence for mechanical motion.'}],67);
 assert.equal(p.clips.length,1);assert.equal(p.clips[0].end,67);
});

test('a returned slide illustrating the current explanation does not create a new topic',()=>{
 const rows=[{start:0,end:30,text:'We explain production methods. The example introduces a useful mechanism.'},
  {start:30,end:60,text:'For example the mechanism follows from the same principles.'},
  {start:60,end:90,text:'Now let us discuss diagnosis. A running process may still fail.'},
  {start:90,end:120,text:'Here is the configuration used to check the process.'},
  {start:120,end:150,text:'The configuration detects failures and the result completes our explanation.'}];
 const p=planCompleteTopics(rows,150,{chapters:[{start:0,end:60,title:'Production methods'},{start:60,end:90,title:'Diagnosis'},{start:90,end:150,title:'Production methods'}]});
 assert.equal(p.clips.length,2);assert.equal(p.clips[1].end,150);
});
test('first detected introduction covers preceding welcome without fixed video timestamps',()=>{
 const rows=[{start:0,end:20,text:'Welcome to our new course. My name is Alice.'},{start:20,end:40,text:'Today we will discuss the syllabus.'},
  {start:40,end:65,text:'Now let us discuss photosynthesis. Plants convert light into chemical energy.'},
  {start:65,end:95,text:'For example chlorophyll absorbs light and the process produces sugars.'}];
 const p=planCompleteTopics(rows,95,{chapters:[{start:12,end:40,title:'About me',key:'introduction'},{start:40,end:95,title:'Photosynthesis'}]});
 assert.equal(p.clips.length,1);assert.equal(p.clips[0].start,40);
});

test('Russian topic transitions preserve the end of the preceding explanation',()=>{
 const rows=[{start:0,end:30,text:'Рассмотрим линейные функции. График линейной функции представляет собой прямую с постоянным наклоном.'},
 {start:30,end:60,text:'Например, увеличение аргумента на единицу изменяет значение на коэффициент наклона. Так мы получили результат.'},
 {start:60,end:85,text:'Теперь рассмотрим квадратные уравнения. Дискриминант определяет количество действительных корней.'},
 {start:85,end:120,text:'Например, положительный дискриминант даёт два различных корня. Подстановка проверяет полученное решение.'}];
 const p=planCompleteTopics(rows,120);assert.equal(p.clips.length,2);assert.equal(p.clips[1].start,60);
 assert.match(p.clips[0].boundaryEvidence.last,/результат/);
});
test('an unfinished worked example is not split by a changed illustration',()=>{
 const rows=[{start:0,end:30,text:'Let us solve this problem. First we derive a relationship between the given variables.'},
 {start:30,end:70,text:'The first calculation yields an intermediate value which we will use in the next step.'},
 {start:70,end:110,text:'For example another diagram illustrates the same relationship with different labels.'},
 {start:110,end:150,text:'Substitution into the relationship yields the final answer. That completes the solution.'}];
 assert.equal(planCompleteTopics(rows,150,{sceneCuts:[70]}).clips.length,1);
});
test('generic titles cannot turn unrelated image/volume/architecture speech into Docker lessons',()=>{
 const p=planCompleteTopics([{start:0,end:30,text:'Now let us discuss Renaissance architecture. The image shows a dome and classical columns.'},
 {start:30,end:65,text:'The volume of the building creates an open space, and the architecture allows light to enter.'}],65);
 assert.ok(p.clips.length);assert.ok(p.clips.every(c=>!/Docker|контейнер/u.test(c.title)));
});

import {inspectLectureCoverage} from '../src/coverage-inspection.js';
test('OCR chapters without verified identities are not reported as verified separate topics',()=>{
 const review=inspectLectureCoverage([{start:0,end:60,title:'An observed slide'}],[{start:0,end:60}],
  [{start:0,end:60,text:'This is an explanation with enough spoken words to review the actual source carefully, while the slide heading alone does not establish the semantic completeness of the resulting lesson.'}]);
 assert.notEqual(review.rows[0].status,'separate-video');
});
