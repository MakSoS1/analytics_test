import test from 'node:test';
import assert from 'node:assert/strict';
import {isLectureHousekeeping,meaningfulTitle,topicEvidence} from '../src/lecture-semantics.js';
import {isEducationalSpeech,planCompleteTopics} from '../src/complete-topics.js';
import {topicSummary} from '../src/microtopic-catalog.js';
import {buildVerifiedLessonScreenplays} from '../src/lesson-screenplay.js';
const row=(start,end,text)=>({start,end,text});

test('real uploaded lecture starts with title, About me and Lecture 1 brief, not a Docker lesson',()=>{
 const entries=[
  row(0,10,'Highload High-Availability Systems Lecture 1'),
  row(25,52,'About me. I have 15+ years of development experience, leading and creating software.'),
  row(60,85,'15+ years of development and creating billing system for highload.'),
  row(90,120,'Lecture 1 brief. What is container, difference from Virtual Machine, Docker architecture, image model, Dockerfile, lifecycle and networking.'),
  row(300,335,'Containers vs Virtual Machines. A VM is a full hardware virtualization, while Docker containers share the host kernel.'),
  row(340,375,'For example virtual machines have an operating system while a container isolates only the application.'),
  row(380,403,'Therefore containers use fewer resources and start faster than a VM.'),
 ];
 assert.equal(isLectureHousekeeping(entries[1].text),true);
 assert.equal(isLectureHousekeeping(entries[2].text),true);
 assert.equal(isLectureHousekeeping(entries[3].text),true);
 const result=planCompleteTopics(entries,600);
 assert.equal(result.clips.length,1);
 assert.equal(result.clips[0].segments[0].start,300);
 assert.equal(result.clips[0].title,'Контейнеры и виртуальные машины');
 assert.equal(result.summary.excludedUtterances,4);
});
test('do not drop a real teaching explanation just because lecturer says today',()=>{
 const teaching='Today we discuss Docker networking. Bridge networks isolate containers because they connect to docker0.';
 assert.equal(isLectureHousekeeping(teaching),false);
 assert.equal(isEducationalSpeech(teaching),true);
});
test('microtopic title is short and grounded by spoken terms',()=>{
 assert.equal(meaningfulTitle([row(0,20,'Dockerfile: production-grade multi-stage build uses two images.')]),'Dockerfile и сборка образа');
 assert.equal(meaningfulTitle([row(0,20,'Docker Networking uses bridge and overlay for multi-host networks.')]),'Сети Docker: bridge и overlay');
 assert.equal(meaningfulTitle([row(0,20,'Docker lifecycle starts with created, running, stopped and deleted.')]),'Жизненный цикл и здоровье контейнера');
 assert.equal(topicEvidence('Today: Kubernetes and kubectl cluster').key,'kubernetes');
});
test('catalogue retains literal original quotes and source timecodes',()=>{
 const chunks=[
  row(300,320,'Docker containers share host kernel, avoiding a complete guest operating system.'),
  row(321,340,'For example, the start is faster than a VM.'),
  row(360,378,'Therefore they need less overhead.')
 ];
 const source={id:'vm',start:300,end:378,segments:[{start:300,end:340},{start:360,end:378}],title:'Контейнеры и виртуальные машины'};
 const [clip]=buildVerifiedLessonScreenplays([source],chunks);
 const info=topicSummary(clip,chunks);
 assert.deepEqual(info.spoken.map(s=>s.start),[300,321,360]);
 assert.deepEqual(info.pieces,[{start:300,end:340},{start:360,end:378}]);
 assert.ok(info.screenplay.every(x=>x.source==='lecture'));
 assert.ok(info.screenplay.every(x=>chunks.some(c=>c.text===x.quote)));
});
