import test from 'node:test';import assert from 'node:assert/strict';
import {isNonTeachingIntroduction,inferEditorialBeats,buildVerifiedLessonScreenplays,storyboardReadyForRendering} from '../src/lesson-screenplay.js';
test('a Docker lecture begins after lecturer biography, not the first timestamp',()=>{
 const chunks=[
  {start:0,end:19,text:'Меня зовут Алексей, я работаю преподавателем, моя должность доцент кафедры.'},
  {start:20,end:48,text:'Сейчас расскажу о расписании занятий и организационных правилах курса.'},
  {start:120,end:148,text:'Docker контейнеры позволяют изолировать процессы и запускать одинаковые образы на разных серверах.'},
  {start:150,end:190,text:'Например зависимости приложения находятся внутри образа, поэтому окружение воспроизводимо.'},
  {start:195,end:225,text:'Таким образом контейнеры Docker упрощают развёртывание и дают повторяемый результат.'}
 ];
 assert.equal(isNonTeachingIntroduction(chunks[0].text),true);
 const [clip]=buildVerifiedLessonScreenplays([{id:'docker',start:0,end:225,segments:[{start:0,end:225}]}],chunks);
 assert.equal(clip.screenplay.beats[0].start,120);
 assert.equal(clip.segments[0].start,120);
 assert.equal(clip.editorialStatus,'proposed');
 assert.ok(storyboardReadyForRendering(clip));
});
test('no technical lesson is not incorrectly marked ready',()=>{
 const [clip]=buildVerifiedLessonScreenplays([{id:'bio',start:0,end:30}],[
  {start:0,end:30,text:'Меня зовут преподаватель, моя должность, доцент кафедры.'}
 ]);
 assert.equal(storyboardReadyForRendering(clip),false);
 assert.equal(clip.editorialStatus,'needs-more-context');
});
test('one 20 minute exercise remains one screenplay',()=>{
 const chunks=[
  {start:0,end:25,text:'Решим практическую задачу, для этого вычислим производную функции.'},
  {start:100,end:120,text:'Далее подставляем значение и упрощаем выражение.'},
  {start:1190,end:1220,text:'Таким образом получили ответ и проверили результат задачи.'}
 ];
 const [c]=buildVerifiedLessonScreenplays([{id:'long',start:0,end:1220,segments:[{start:0,end:1220}]}],chunks);
 assert.equal(c.segments[0].end,1220);
 assert.equal(c.screenplay.beats.length,3);
});

test('agenda with technical keywords is not validated as a finished Docker lesson',()=>{
 const agenda={start:0,end:20,text:'Сегодня мы поговорим о Docker, Kubernetes и CI/CD, рассмотрим план нашего курса и что будет дальше.'};
 assert.equal(isNonTeachingIntroduction(agenda.text),true);
 const [clip]=buildVerifiedLessonScreenplays([{id:'agenda',start:0,end:20}], [agenda]);
 assert.equal(clip.screenplay.quality.readyForReview,false);
 assert.equal(clip.editorialStatus,'needs-more-context');
});
test('unfinished final explanation is not misleadingly called a takeaway',()=>{
 const chunks=[
  {start:0,end:10,text:'Docker контейнеры позволяют изолировать процессы и приложения, используя образы для запуска.'},
  {start:10,end:25,text:'Например контейнер получает независимую файловую систему и собственную конфигурацию сети.'}
 ];
 const [clip]=buildVerifiedLessonScreenplays([{id:'unfinished',start:0,end:25}],chunks);
 assert.equal(clip.screenplay.beats.at(-1).role,'explanation');
 assert.equal(clip.screenplay.quality.finished,false);
 assert.ok(clip.screenplay.quality.issues.some(x=>x.includes('итог')));
});
