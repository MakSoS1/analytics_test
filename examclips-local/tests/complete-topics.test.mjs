import test from 'node:test';
import assert from 'node:assert/strict';
import {isEducationalSpeech,planCompleteTopics} from '../src/complete-topics.js';
import {storyDuration,sourceSegments} from '../src/selective-stories.js';
const row=(start,end,text)=>({start,end,text});
const fact='Docker контейнеры позволяют изолировать приложение и сохранять зависимости в образах. Например обновлять сервисы можно без перестройки окружения.';
test('no proportion or quota even when 90% of lecture is useful',()=>{
 const chunks=Array.from({length:30},(_,i)=>
  row(i*20,i*20+18,fact+' Поэтому система остаётся воспроизводимой на сервере.'));
 const r=planCompleteTopics(chunks,600);
 assert.equal(r.clips.length,1);
 assert.ok(r.summary.keptPercent>=80,r.summary.keptPercent);
 assert.equal(r.summary.keptUtterances,30);
 assert.equal(r.summary.excludedUtterances,0);
});
test('one worked practical task may be a single 20-minute vertical video',()=>{
 const words='Подставляем значения в формулу, вычисляем производную и проверяем решение уравнения. Это важный шаг задачи.';
 const rows=[row(0,15,'Сейчас разберём практическую задачу по вычислению производной. Условие задачи следующее.'),
 ...Array.from({length:79},(_,i)=>row(15+i*15,30+i*15,words)),
 row(1200,1215,'Таким образом задача решена, мы получили ответ и проверили вычисления.'),
 row(1220,1240,'Теперь перейдём к другой теме: алгоритм поиска пути в графе и его сложность.')
 ];
 const res=planCompleteTopics(rows,1240);
 assert.equal(res.clips.length,2);
 assert.equal(res.clips[0].kind,'worked-exercise');
 assert.ok(storyDuration(res.clips[0])>=1200,'Practical worked example was wrongly split');
 assert.ok(storyDuration(res.clips[0])<1220);
});
test('remove only obvious breaks/technical checks and long ASR gaps, keep examples',()=>{
 const rows=[row(5,30,fact),row(40,55,'Проверка микрофона, подождите минуту.'),
  row(230,255,'Например контейнер Docker можно запустить из образа; это позволяет переносить приложения.'),
  row(260,278,'Расписание следующего занятия, подождите минуту, перерыв на чай.'),
  row(285,310,'Таким образом эти контейнеры позволяют независимо обновлять сервисы и масштабировать нагрузку.')];
 const r=planCompleteTopics(rows,360);
 assert.equal(r.summary.excludedUtterances,2);
 assert.equal(r.summary.keptUtterances,3);
 assert.ok(r.summary.discardedSeconds>200);
 assert.ok(r.clips.some(c=>sourceSegments(c).length>=2));
});
test('multiple explicit lesson transitions yield several complete microtopics',()=>{
 const rows=[row(0,18,fact),
 row(20,44,'Следующая тема — балансировка нагрузки; запросы распределяются между серверами.'),
 row(45,75,'Например балансировщик позволяет масштабировать систему, потому что запросы идут на разные узлы.'),
 row(100,135,'Теперь перейдём к другой теме: сетевые протоколы, маршрутизация и обработка адресов.')];
 const r=planCompleteTopics(rows,140);
 assert.equal(r.clips.length,3);
 assert.ok(r.clips.every(c=>c.status==='needs-review'));
});
test('no fabricated video if no meaningful speech',()=>{
 assert.deepEqual(planCompleteTopics([],3600).clips,[]);
 const r=planCompleteTopics([row(10,15,'Проверка микрофона, подождите минуту.')],100);
 assert.equal(r.clips.length,0);
});
test('a plain educational lesson with no keywords is preserved by default',()=>{
 const r=planCompleteTopics([row(0,20,'Массив представляет собой упорядоченную последовательность элементов.'),
 row(21,52,'Каждый элемент находится по индексу; для обращения к нему используется смещение.')],60);
 assert.equal(r.summary.keptUtterances,2);
 assert.ok(r.clips.length>0);
});

test('late Docker teaching is selected instead of course introduction and lecturer biography',()=>{
 const rows=[
  row(0,10,'Здравствуйте, меня зовут Алексей, я преподаю Docker.'),
  row(11,25,'Сегодня мы поговорим о Docker, Kubernetes и CI/CD, рассмотрим план нашего курса и что будет дальше.'),
  row(26,45,'Моя должность доцент кафедры, я работаю преподавателем уже много лет.'),
  row(80,115,'Docker контейнеры позволяют изолировать приложения и зависимости внутри образа, поэтому перенос между серверами повторяем.'),
  row(118,145,'Например контейнер запускается из образа и использует собственную файловую систему и сетевые настройки.'),
  row(146,168,'Таким образом получаем переносимую среду выполнения для каждого приложения.')
 ];
 const planned=planCompleteTopics(rows,180);
 assert.equal(planned.summary.excludedUtterances,3);
 assert.equal(planned.summary.keptUtterances,3);
 assert.equal(planned.clips.length,1);
 assert.equal(sourceSegments(planned.clips[0])[0].start,80);
 assert.ok(storyDuration(planned.clips[0])>70);
});
test('teaching explanation inside an opening phrase is not silently discarded',()=>{
 const explanation='Сегодня рассмотрим Docker на примере: контейнеры позволяют изолировать зависимости и разворачивать приложение независимо от ОС.';
 assert.equal(isEducationalSpeech(explanation),true);
 assert.equal(isEducationalSpeech('Today we will cover Docker, Kubernetes, PostgreSQL, and course logistics.'),false);
});
