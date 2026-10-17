import test from 'node:test';
import assert from 'node:assert/strict';
import {lessonIdentity,distinctVerifiedConcept,rowLessonIdentity} from '../src/lesson-identity.js';
import {consolidateMicrotopics} from '../src/topic-editorial-guardrails.js';
import {planCompleteTopics} from '../src/complete-topics.js';
import {storyDuration} from '../src/selective-stories.js';
const chapter={start:800,end:1450,title:'Dockerfile: сборка, образы и производственные практики',key:'dockerfile'};
const row=(start,end,text)=>({start,end,text});
const group=(rows)=>({rows,chapter});
const title=g=>lessonIdentity(g.rows,g.chapter)?.title;
test('screenshot regression: 13:20 / 13:38 / 14:00 / 14:21 / 15:00 form coherent Dockerfile lesson(s), never container-definition clones',()=>{
 // This reproduces the EXACT visual intervals of the reported screen.
 // Phrases are synthetic examples, NOT claims about original audio.
 const raw=[
  group([row(800,817,'Docker containers rely on images to run the application, as we introduced previously.')]),
  group([row(818,839,'Now in a Dockerfile, images are built from instructions and a base image.')]),
  group([row(840,861,'Docker images contain several layers, each corresponding to a change.')]),
  group([row(861,900,'The FROM instruction selects the base image and RUN installs packages. COPY includes our application files.')]),
  group([
   row(900,1030,'Dockerfile multi-stage build separates compile and runtime stages, keeping build tools out of the final image.'),
   row(1030,1160,'For example, the first stage compiles the code, and the second stage copies the resulting binary to the final image.'),
   row(1160,1290,'Multi-stage Dockerfile builds also reduce image size by leaving intermediate dependencies behind.'),
   row(1290,1426,'Therefore multi-stage build allows deploying a smaller runtime image with only necessary files.')
  ])
 ];
 assert.deepEqual(raw.slice(0,4).map(x=>x.rows[0].start),[800,818,840,861]);
 assert.ok(raw.slice(0,4).every(x=>title(x)!=='Что такое контейнер Docker'));
 const refined=consolidateMicrotopics(raw);
 assert.ok(refined.groups.length<=2,
  'The original five fragments must not persist as separate microvideos: '+refined.groups.length);
 assert.equal(refined.groups[0].rows[0].start,800);
 assert.ok(refined.groups[0].rows.at(-1).end>=900,'4 introductory fragments should be one context');
 const headlines=refined.groups.map(title);
 assert.ok(headlines.every(x=>/Dockerfile|образ/i.test(x)),headlines.join(' | '));
 assert.equal(new Set(headlines).size,headlines.length,'The gallery must not repeat an identical generic headline');
});
test('a Dockerfile mention or Docker container word cannot be mislabelled as teaching the definition of containers',()=>{
 const phrases=[
  'Docker containers use a Dockerfile to build an image.',
  'Docker is the runtime for images and containers.',
  'Now an image has read-only filesystem layers.',
  'Dockerfile has a base image.'
 ];
 for(const text of phrases){
  assert.notEqual(lessonIdentity([row(800,824,text)],chapter)?.title,'Что такое контейнер Docker');
  assert.notEqual(rowLessonIdentity(row(810,822,text),chapter)?.key,'container-definition');
 }
 assert.match(lessonIdentity([row(810,831,phrases[0])],chapter).title,/Dockerfile/);
});
test('two genuinely different Dockerfile methods with source support must remain distinct',()=>{
 const cache=group([
  row(1000,1026,'Docker build cache reuses the previous image layer when input remains the same.'),
  row(1026,1056,'Layer caching and cache invalidation make Dockerfile rebuilds much faster.')
 ]);
 const multi=group([
  row(1058,1088,'Multi-stage Dockerfile builds separate compilation and runtime images.'),
  row(1088,1119,'A multi-stage Dockerfile uses the output of a builder stage in a smaller final image.')
 ]);
 assert.equal(distinctVerifiedConcept(cache,multi),true);
 const groups=consolidateMicrotopics([cache,multi]).groups;
 assert.equal(groups.length,2);
 assert.notEqual(title(groups[0]),title(groups[1]));
});
test('same Dockerfile chapter and coherent continuously spoken ASR is never split into repeated 17s 21s 21s 39s reels',()=>{
 const transcript=[
  row(800,817,'Docker containers depend on images. The Dockerfile specifies how the application image is assembled.'),
  row(818,839,'Now Dockerfile instructions can create the image from an existing base image.'),
  row(840,861,'For example, the image has separate layers which can be reused during the next build.'),
  row(861,900,'FROM chooses a base image, RUN executes a command, and COPY moves application content inside it.'),
  row(900,956,'This lets us write an image build that starts from a base system and installs required dependencies.'),
  row(957,1010,'A Dockerfile build follows these steps to produce the final container image with our application.'),
  row(1011,1070,'Because each image layer is stored, unchanged steps in later builds may be reused.'),
  row(1071,1140,'For example, changing only application code does not require running all earlier installation instructions again.')
 ];
 const plan=planCompleteTopics(transcript,1450,{chapters:[chapter]});
 assert.ok(plan.clips.length<=2,JSON.stringify(plan.clips.map(c=>({title:c.title,seconds:c.outputSeconds}))));
 assert.ok(plan.clips.every(c=>storyDuration(c)>=50),'An 18-second isolated caption is not a standalone educational short');
 assert.ok(plan.clips.every(c=>!/Что такое контейнер/i.test(c.title)),plan.clips.map(c=>c.title).join(' | '));
 assert.ok(plan.clips.every(c=>c.chapter?.key==='dockerfile'));
});
