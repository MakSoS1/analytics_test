import test from 'node:test';
import assert from 'node:assert/strict';
import {dedupeTranscriptRows,consolidateMicrotopics,assignExclusiveSource} from '../src/topic-editorial-guardrails.js';
import {planCompleteTopics} from '../src/complete-topics.js';
import {sourceSegments,storyDuration} from '../src/selective-stories.js';
const row=(start,end,text)=>({start,end,text});
const chapter={key:'docker-networking',title:'Docker Networking',start:2400,end:3000};
const g=(rows,owner=chapter)=>({rows,chapter:owner});
const explanation='Bridge networks connect Docker containers through virtual network interfaces, which allow services on one host to communicate.';
test('5s and 8s isolated teaching hints never become standalone exported microtopics',()=>{
 const {groups,omitted}=consolidateMicrotopics([
  g([row(100,105,'Now let us see a network mode.')]),
  g([row(200,208,'Docker bridge connects containers.')]),
  g([row(250,275,explanation),row(276,304,'For example, port mapping forwards requests to container services.')])
 ]);
 assert.equal(groups.length,1);
 assert.equal(groups[0].rows.length,2);
 assert.equal(omitted.length,2);
 const plan=planCompleteTopics([
  row(1,6,'Docker bridge mode'),
  row(65,70,'Docker overlay mode')
 ],90);
 assert.ok(plan.clips.every(c=>storyDuration(c)>=12));
});
test('consecutive small remarks about same concept form one substantial lesson',()=>{
 const result=consolidateMicrotopics([
  g([row(5,12,'Docker networking allows services to communicate, using bridge networking and IP addresses.')]),
  g([row(13,21,'Bridge networks connect containers to a software switch and isolate services.')]),
  g([row(23,30,'For example, two containers connect to the same bridge and exchange requests.')]),
  g([row(30,38,'The bridge does not automatically connect containers across different hosts.')]),
  g([row(38,47,'Therefore overlay networking is needed to connect applications on separate servers.')])
 ]);
 assert.ok(result.groups.length<=2,JSON.stringify(result.groups.map(g=>g.rows.length)));
 assert.ok(result.groups.every(g=>g.rows[0].start>=0));
});
test('separate substantive network explanations sharing a slide remain different topics',()=>{
 const groups=[
  g([row(2450,2484,'Bridge network connects containers on a host through a virtual switch.'),row(2490,2523,'For example Docker bridge maps exposed ports.')]),
  g([row(2740,2772,'Overlay network connects containers across multiple machines in a cluster.'),row(2773,2803,'Docker overlay allows multi-host services to communicate.')])
 ];
 const result=consolidateMicrotopics(groups);
 assert.equal(result.groups.length,2);
});
test('ASR duplicate with repeated timestamp is rejected but later genuine lesson steps remain',()=>{
 const exact='Подставляем значения в формулу, вычисляем производную и проверяем результат решения.';
 const items=[
  row(0,30,'Решим одну задачу. Рассмотрим практическое вычисление производной функции.'),
  row(30,45,exact),row(30.1,45,exact),
  ...Array.from({length:78},(_,i)=>row(45+i*15,60+i*15,exact)),
  row(1215,1240,'Таким образом мы получили итоговое решение.')
 ];
 const result=dedupeTranscriptRows(items);
 assert.equal(result.removed.length,1);
 assert.ok(result.rows.length>=80);
 const planned=planCompleteTopics(items,1240);
 assert.equal(planned.clips.length,1);
 assert.ok(storyDuration(planned.clips[0])>1100,'Multi-step practical explanation must stay continuous');
});
test('return to same slide is not a duplicate by itself; verbatim repeat without novel facts is',()=>{
 const fullA=g([row(100,131,explanation),row(132,162,'For example two services on one host communicate over their bridge network.')]);
 const extra=g([row(250,285,'Bridge networks can also configure port mapping and bind routes to specific network interfaces.'),
 row(286,311,'For example a port can be bound only to a loopback interface.')]);
 const repeat=g([row(500,531,explanation),row(532,562,'For example two services on one host communicate over their bridge network.')]);
 const review=consolidateMicrotopics([fullA,extra,repeat]);
 assert.equal(review.groups.length,2,'Only near-verbatim fully redundant microtopic should be suppressed');
 assert.equal(review.omitted.length,2);
});
test('exclusive source ownership removes duplicated seconds at ASR/scene boundary',()=>{
 const actual=assignExclusiveSource([
  {title:'A',start:0,end:31,segments:[{start:0,end:31}]},
  {title:'B',start:30.8,end:61,segments:[{start:30.8,end:61}]},
  {title:'C',start:60.88,end:91,segments:[{start:60.88,end:91}]}
 ]);
 assert.equal(actual.length,3);
 const all=actual.flatMap(c=>sourceSegments(c)).sort((a,b)=>a.start-b.start);
 for(let i=1;i<all.length;i++)
  assert.ok(all[i].start>=all[i-1].end-1e-8,'Duplicate output seconds across clips');
 assert.equal(all[1].start,31);
 assert.equal(all[2].start,61);
});
test('chapter lesson planner never emits a 7s microvideo even if explicitly announced',()=>{
 const rows=[
 row(100,108,'Next topic: Docker bridge, which connects containers.'),
 row(110,118,'Next topic: Docker overlay, which joins machines.'),
 row(120,128,'Next topic: Docker host network mode.')];
 const result=planCompleteTopics(rows,140,{chapters:[{start:90,end:140,title:'Docker Networking',key:'docker-networking'}]});
 assert.ok(result.clips.every(c=>storyDuration(c)>=12));
});
