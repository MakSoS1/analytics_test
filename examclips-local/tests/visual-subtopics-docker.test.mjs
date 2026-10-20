import test from 'node:test';
import assert from 'node:assert/strict';
import {DOCKER_VISUAL_TOPICS,dockerVisualSubtopics,applyVisualSubtopicGuides} from '../src/visual-subtopic-hints.js';
import {lectureVisualReference} from '../src/lecture-outline.js';
import {planCompleteTopics} from '../src/complete-topics.js';
import {sourceSegments,storyDuration} from '../src/selective-stories.js';
const media={name:'HAHL2026_Lecture01_Docker.mp4',duration:3590.341,width:1600,height:900};
const chapter=lectureVisualReference(media);
const phrases={
 'containers-vs-vm':'Containers are isolated processes in Linux. Virtual machines require their own kernels, while lightweight Docker containers share the host kernel.',
 'docker-architecture':'The Docker daemon connects the command line interface to containerd and runC. Images are distributed as filesystem layers.',
 'dockerfile':'Dockerfile instructions build an image through FROM RUN COPY and WORKDIR. Caching image layers and multi-stage builds make repeated builds efficient.',
 'container-lifecycle':'Docker container lifecycle has created and running states. Health check, graceful SIGTERM shutdown, restart policies and Docker kill control services.',
 'docker-storage':'Docker volume storage retains persistent data. Bind mounts share host directories. Stateless containers need external persistence.',
 'docker-networking':'Docker networking uses bridge, custom user-defined bridge, host mode, none network and overlay across hosts for services.',
 'resource-limits':'CPU and memory limits use cgroups. Resource isolation prevents containers from exhausting resources on their host.'
};
const makeRows=()=>{
 const rows=[];
 for(const guide of DOCKER_VISUAL_TOPICS){
  const span=guide.end-guide.start;
  const full=phrases[guide.chapterKey]+' '+guide.title+' '+guide.title+'.';
  for(let i=0;i<4;i++){
   const start=guide.start+span*i/4+.3;
   const end=guide.start+span*(i+1)/4-.3;
   if(end-start<1)continue;
   rows.push({start,end,text:full});
  }
 }
 return rows.sort((a,b)=>a.start-b.start);
};
test('exact 59:50 original has 25 visual cues, not a forced fixed output count',()=>{
 assert.equal(dockerVisualSubtopics(media).length,25);
 assert.equal(dockerVisualSubtopics({...media,name:'different-lecture.mp4'}).length,0);
 assert.equal(dockerVisualSubtopics({...media,width:1280}).length,0);
 assert.equal(DOCKER_VISUAL_TOPICS[0].start,275);
 assert.equal(DOCKER_VISUAL_TOPICS.at(-1).end,3200);
});
test('actual original visual checkpoints + sustained artificial ASR reveal multiple topics PER chapter',()=>{
 const rows=makeRows();
 const planned=planCompleteTopics(rows,media.duration,{chapters:chapter,
    visualHints:dockerVisualSubtopics(media)});
 assert.ok(planned.summary.visualEvidenceSplitCount>4,
  JSON.stringify(planned.summary));
 const dockerfile=planned.clips.filter(c=>c.chapter?.key==='dockerfile');
 const networking=planned.clips.filter(c=>c.chapter?.key==='docker-networking');
 assert.ok(dockerfile.length>=3,'Dockerfile should not become one huge video: '+JSON.stringify(dockerfile.map(c=>[c.title,c.start,c.end])));
 assert.ok(networking.length>=2,'Networking should not become one huge video: '+JSON.stringify(networking.map(c=>[c.title,c.start,c.end])));
 assert.ok(planned.clips.every(c=>storyDuration(c)>=12));
 assert.ok(planned.clips.every(c=>!/(lecture 1|about me|биограф)/iu.test(c.title)));
 const segments=planned.clips.flatMap(c=>sourceSegments(c));
 for(let i=1;i<segments.length;i++)
  assert.ok(segments[i].start>=segments[i-1].end-.001,'No repeated source seconds');
});
test('visual hint never invents a topic without speech on both sides',()=>{
 const guides=DOCKER_VISUAL_TOPICS.filter(h=>h.chapterKey==='dockerfile');
 const base={rows:[
   {start:810,end:845,text:'Dockerfile defines the base image using a FROM instruction.'},
   {start:849,end:880,text:'The RUN directive executes a shell command during image construction.'},
   {start:881,end:920,text:'The COPY instruction places source files into the resulting image.'}
  ],chapter:chapter.find(c=>c.key==='dockerfile')};
 const separated=applyVisualSubtopicGuides([base],guides);
 assert.equal(separated.length,1,'A slide heading is not sufficient to invent a second lesson');
});
test('actual media map excludes initial course intro despite technical words',()=>{
 const rows=[
  {start:80,end:140,text:'About me, I have years of experience. Lecture outline: Docker containers, networking and virtual machines.'},
  ...makeRows().slice(0,16)
 ];
 const plan=planCompleteTopics(rows,media.duration,{chapters:chapter,visualHints:dockerVisualSubtopics(media)});
 assert.ok(plan.clips[0]?.start>=275);
});
