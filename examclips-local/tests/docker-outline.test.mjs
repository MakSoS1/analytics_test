import test from 'node:test';
import assert from 'node:assert/strict';
import {lectureVisualReference,chapterForTime,normalizeSlideChapters} from '../src/lecture-outline.js';
import {planCompleteTopics} from '../src/complete-topics.js';
import {buildVerifiedLessonScreenplays} from '../src/lesson-screenplay.js';
import {storyDuration,sourceSegments} from '../src/selective-stories.js';
import {chaptersFromHeadings,slideHeadingFromLines} from '../src/slide-chapter-index.js';
const meta={name:'HAHL2026_Lecture01_Docker.mp4',duration:3590.341,width:1600,height:900};
const row=(start,end,text)=>({start,end,text});
const chapters=lectureVisualReference(meta);
test('real Docker video physical identity activates only its inspected outline',()=>{
 assert.ok(chapters.length>=12);
 assert.equal(chapters[0].key,'introduction');
 assert.ok(chapterForTime(chapters,60)?.key==='introduction');
 assert.ok(chapterForTime(chapters,120)?.key==='introduction');
 assert.equal(chapterForTime(chapters,555)?.key,'docker-architecture');
 assert.equal(chapterForTime(chapters,2600)?.key,'docker-networking');
 assert.deepEqual(lectureVisualReference({...meta,name:'other-course.mp4'}),[]);
 assert.deepEqual(lectureVisualReference({...meta,duration:250}),[]);
});
test('Docker 59m lecture yields consecutive distinct subtopics and excludes lecturer bio/course',()=>{
 const t=[
  row(8,25,'Hello my name is lecturer. I have 15 years experience building large systems.'),
  row(35,58,'About me, my background, I developed billing systems for years.'),
  row(119,151,'Lecture 1 brief. We will cover containers, Dockerfile, images, architecture and networking.'),
  row(198,215,'So today we will cover containers, virtual machines, and Docker architecture.'),
  row(245,267,'Containers are isolated processes sharing the operating system kernel.'),
  row(268,289,'Containers are lightweight execution environments with separated dependencies.'),
  row(314,339,'Virtual machines are complete guest operating systems with their own kernels.'),
  row(340,372,'Unlike a container, each virtual machine virtualizes the hardware and runs a full OS.'),
  row(510,541,'Docker architecture uses a daemon and container runtime called containerd.'),
  row(548,575,'The Docker daemon connects the CLI and containerd runtime to launch containers.'),
  row(622,646,'A Docker image is built from filesystem layers for caching and distribution.'),
  row(651,678,'Each image layer stores the changes and Docker can reuse a layer.'),
  row(801,834,'Dockerfile instructions describe building an application image step by step.'),
  row(839,864,'For example Docker build executes each instruction to create a new layer.'),
  row(1446,1470,'Container lifecycle begins with created, running and stopped states.'),
  row(1471,1502,'Docker stop requests SIGTERM, whereas kill immediately interrupts the process.'),
  row(2190,2225,'Persistent storage uses Docker volumes to keep data beyond container deletion.'),
  row(2226,2254,'For example bind mounts connect a host directory to container storage.'),
  row(2450,2484,'Bridge networks connect containers within one host while controlling addresses.'),
  row(2490,2523,'For example Docker bridge connects application services through virtual interfaces.'),
  row(2740,2772,'Overlay network connects containers across multiple hosts via a virtual network.'),
  row(2773,2803,'Docker overlay networks make multi-host communication possible.'),
  row(3070,3101,'CPU and memory limits ensure one container does not starve others.'),
  row(3104,3130,'Therefore containers should use cgroups to limit resource consumption.')
 ];
 const plan=planCompleteTopics(t,meta.duration,{chapters});
 assert.equal(plan.summary.excludedIntroSeconds,8+23+32+17);
 assert.ok(plan.excluded.some(x=>x.start===119),'Course agenda must not appear');
 assert.ok(plan.clips.length>=8,JSON.stringify(plan.clips.map(c=>c.title)));
 const first=plan.clips[0];
 assert.ok(sourceSegments(first)[0].start>=245,'No lecture opening may remain');
 const titles=plan.clips.map(c=>c.title);
 assert.ok(titles.some(x=>/Что такое контейнер/.test(x)),JSON.stringify(titles));
 assert.ok(titles.some(x=>/виртуальн/.test(x)),JSON.stringify(titles));
 assert.ok(titles.some(x=>/сети|bridge/i.test(x)),JSON.stringify(titles));
 assert.ok(titles.some(x=>/Dockerfile/.test(x)),JSON.stringify(titles));
 assert.ok(plan.clips.every(c=>c.chapter?.title),'Each clip has a chapter reference');
 const scripts=buildVerifiedLessonScreenplays(plan.clips,t);
 assert.ok(scripts.every(c=>c.screenplay.schema===2));
 assert.ok(scripts.every(c=>c.screenplay.summary.every(s=>s.evidence.every(e=>
   t.some(x=>x.start===e.start&&x.text===e.quote)))));
});
test('chapter evidence does not create artificial clips from slides without speech',()=>{
 const r=planCompleteTopics([row(2600,2630,'Проверка микрофона, подождите минуту')],meta.duration,{chapters});
 assert.equal(r.clips.length,0);
});
test('no duration quota: worked task spans 20 minutes even with slide cuts',()=>{
 const rows=[row(5,25,'Решим следующую задачу. Найдём производную функции.')];
 for(let i=0;i<80;i++)rows.push(row(25+i*15,40+i*15,'Подставляем значения в формулу, вычисляем производную и проверяем результат решения.'));
 rows.push(row(1226,1239,'Таким образом мы получили ответ на исходную задачу.'));
 const planned=planCompleteTopics(rows,1245,{sceneCuts:[40,80,200,600,1000]});
 assert.equal(planned.clips.length,1);
 assert.ok(storyDuration(planned.clips[0])>1200);
});
test('slide OCR header text groups repeated slides but keeps real topic changes',()=>{
 const lines=[
  {text:'ITMO',confidence:98,box:{x0:1050,x1:1120,y0:3,y1:80}},
  {text:'Docker Architecture & Image Model',confidence:87,
    box:{x0:16,x1:660,y0:15,y1:70}}
 ];
 assert.equal(slideHeadingFromLines(lines,1152,220),'Docker Architecture & Image Model');
 const result=chaptersFromHeadings([
   {start:0,title:'About me'},{start:35,title:'About me'},
   {start:110,title:'Lecture 1 brief'},{start:210,title:'Docker Architecture & Image Model'},
   {start:275,title:'Docker Architecture & Image Model'},{start:325,title:'Dockerfile'}
 ],400);
 assert.equal(result.length,4);
 assert.equal(result[0].key,'introduction');
 assert.equal(result[2].title,'Docker Architecture & Image Model');
 assert.equal(result[3].start,325);
});
