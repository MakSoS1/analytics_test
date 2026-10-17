import test from 'node:test';
import assert from 'node:assert/strict';
import {DOCKER_VISUAL_TOPICS} from '../src/visual-subtopic-hints.js';
import {inspectLectureCoverage} from '../src/coverage-inspection.js';
const cue=(start,end,text)=>({start,end,text});
const clip=(id,start,end,visualSection=null)=>({id,title:id,start,end,segments:[{start,end}],visualSection});
test('the 26 original slide concepts are independently accounted for in the UI audit',()=>{
 const rows=[
  cue(800,834,'Dockerfile uses the FROM instruction to select an official base image and RUN executes commands during an application build with several required dependencies.'),
  cue(835,883,'COPY transfers application source files while WORKDIR sets the execution directory, so the complete application image builds reproducibly with each changed instruction.'),
  cue(942,1000,'Docker build cache reuses filesystem layers when dependencies have not changed; this avoids reinstalling packages during repeated builds and reduces compilation time.'),
  cue(1001,1083,'A Dockerfile cache invalidation triggers the subsequent image layers to build again, so command ordering makes a considerable difference to the final build time.'),
  cue(2790,2860,'The host network shares the underlying host machine networking stack directly, removing network isolation and allowing applications inside containers to use host IP addresses and network ports.')
 ];
 const guide=DOCKER_VISUAL_TOPICS;
 const visuals=guide.filter(x=>x.start===800||x.start===938||x.start===2780);
 const report=inspectLectureCoverage(visuals,[
  clip('dockerfile-intro',800,938,'visual-08'),
  clip('huge-network-chapter',2400,3025)
 ],rows);
 assert.equal(report.rows.length,3);
 assert.equal(report.rows[0].status,'separate-video');
 assert.equal(report.rows[1].status,'not-in-clips');
 assert.equal(report.rows[2].status,'merged-into-chapter');
 assert.equal(report.summary.separate,1);
 assert.equal(report.summary.merged,1);
 assert.equal(report.summary.lost,1);
});
test('frame labels without enough recognized speech never count as verified videos',()=>{
 const report=inspectLectureCoverage(DOCKER_VISUAL_TOPICS.slice(0,1),[clip('phantom',275,350)],[cue(290,294,'VM')]);
 assert.equal(report.rows[0].status,'insufficient-transcript');
});
