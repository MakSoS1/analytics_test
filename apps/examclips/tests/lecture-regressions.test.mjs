import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {makeStoryboard} from '../src/scene-model.js';
import {suitableOcrLines} from '../src/editorial-motion.js';

test('unmatched speech retains the last supported panel rather than alternating into blank space',()=>{
 const scene=makeStoryboard({width:1600,height:900,duration:45,
 lines:[{text:'Container isolation',confidence:95,box:{x0:90,y0:200,x1:500,y1:260}}],
 chunks:[{start:0,end:45,text:'An explanation with no matching keywords.'}]});
 assert.ok(scene.beats.every(b=>b.focus===0));
});
test('code is kept as original pixels even when OCR confidence is high',()=>{
 assert.deepEqual(suitableOcrLines({lines:['FROM node:20','WORKDIR /app','COPY . .','RUN npm install','EXPOSE 8080','CMD node server.js']}),[]);
 assert.deepEqual(suitableOcrLines({sourceOnly:true,lines:['A valid long explanation','Another trustworthy sentence']}),[]);
});
test('export uses the source timestamp after every ten-second decoder batch and disjoint cut',async()=>{
 const source=await readFile(new URL('../src/render.js',import.meta.url),'utf8');
 const stub=`
 const seen=[];
 class Output {addVideoTrack(){} addAudioTrack(){} async start(){} async finalize(){} async cancel(){}}
 class BufferTarget {buffer=new ArrayBuffer(1)}
 class CanvasSource {async add(){}}
 class Quality {} class Mp4OutputFormat {}
 const WIDTH=720,HEIGHT=1280;
 const sourceSegments=c=>c.segments;
 const storyDuration=c=>c.segments.reduce((n,p)=>n+p.end-p.start,0);
 const captionSequenceAt=(chunks,time)=>time;
 const paintFrame=(canvas,frame,w,h,layout,focus,caption)=>seen.push(caption);
 const document={createElement:()=>({})}; const VideoEncoder=function(){};
 export {seen};
 `;
 const module=await import('data:text/javascript;base64,'+Buffer.from(stub+source.replace(/^import .*;\n/gm,'')).toString('base64'));
 const media={duration:100,videoSink:{async *samplesAtTimestamps(times){for(const time of times)yield {displayWidth:1600,displayHeight:900,close(){}};}}};
 await module.exportClip(media,{segments:[{start:5,end:27},{start:40,end:52}]},[]);
 assert.equal(module.seen.length,510);
 assert.equal(module.seen[150],15);
 assert.equal(module.seen[300],25);
 assert.equal(module.seen[330],40);
 assert.equal(module.seen[480],50);
 assert.ok(module.seen.every(Number.isFinite));
});

test('no-OCR fallback retains the whole teaching area instead of inventing two crops',()=>{
 const scene=makeStoryboard({width:1600,height:900,duration:45});
 assert.equal(scene.panels.length,1);
 assert.ok(scene.panels[0].rect.w>.9);
});

import {planCompleteTopics} from '../src/complete-topics.js';
test('approximate introduction slide cannot discard a substantive explanation starting before the visual boundary',()=>{
 const rows=[{start:250,end:274,text:'Containers are isolated processes sharing the operating system kernel. This means each application has its own view of files and processes.'},{start:274,end:310,text:'For example namespaces isolate process identifiers and network interfaces while the host kernel is shared.'}];
 const plan=planCompleteTopics(rows,330,{chapters:[{start:0,end:275,title:'Introduction',key:'introduction',confidence:'approximate'},{start:275,end:330,title:'Containers',key:'containers-vs-vm'}]});
 assert.ok(plan.clips.some(c=>c.start===250));
 assert.ok(!plan.excluded.some(c=>c.start===250));
});

import {consolidateMicrotopics} from '../src/topic-editorial-guardrails.js';
test('consolidating a short continuation preserves a visually evidenced topic identity',()=>{
 const chapter={key:'docker-networking'};
 const first={chapter,visualSection:'host',visualTitle:'Host network',rows:[{start:0,end:30,text:'Host mode shares the network namespace of the host and removes bridge translation.'}]};
 const continuation={chapter,rows:[{start:30,end:50,text:'The shared network namespace means the host ports are used directly by this process.'}]};
 const groups=consolidateMicrotopics([first,continuation]).groups;
 assert.equal(groups.length,1);assert.equal(groups[0].visualSection,'host');
});

test('pixel evidence excludes a blank half and fits the actual diagram bounds',()=>{
 const width=160,height=90,pixels=new Uint8ClampedArray(width*height*4).fill(255);
 for(let y=22;y<45;y++)for(let x=12;x<58;x++){
  const at=(y*width+x)*4;pixels[at]=pixels[at+1]=pixels[at+2]=0;
 }
 const scene=makeStoryboard({width,height,duration:30,pixels});
 assert.equal(scene.panels.length,1);
 assert.ok(scene.panels[0].rect.w<.6);
 assert.ok(scene.panels[0].rect.h<.5);
});

import {applyVisualSubtopicGuides} from '../src/visual-subtopic-hints.js';
test('approximate visual split snaps back to an announced spoken transition',()=>{
 const chapter={key:'docker-networking'};
 const rows=[
 {start:0,end:25,text:'Bridge networking connects services inside a host and provides isolated addresses with forwarding rules.'},
 {start:25,end:50,text:'The bridge network enables services to communicate through a virtual switch with explicit routing.'},
 {start:50,end:60,text:'Next one is host. Normally a container gets its own namespace.'},
 {start:60,end:85,text:'The host network removes isolation and shares the host stack with every process inside the container.'},
 {start:85,end:110,text:'Host network improves performance but you give up port safety and isolation between workloads.'}];
 const hints=[{id:'bridge',chapterKey:chapter.key,start:0,end:70,title:'Bridge',terms:/bridge/},{id:'host',chapterKey:chapter.key,start:70,end:110,title:'Host',terms:/host/}];
 const groups=applyVisualSubtopicGuides([{chapter,rows}],hints,{minWords:20});
 assert.equal(groups.length,2);assert.equal(groups[1].rows[0].start,50);
});

import {rowLessonIdentity} from '../src/lesson-identity.js';
import {DOCKER_VISUAL_TOPICS} from '../src/visual-subtopic-hints.js';
test('absence of automatic DNS does not identify a user-defined bridge',()=>{
 assert.notEqual(rowLessonIdentity({text:'There is no automatic name resolution on the default bridge.'},{key:'docker-networking'}).key,'network-userbridge');
});
test('revising the source guide preserves identities used in saved projects',()=>{
 assert.equal(DOCKER_VISUAL_TOPICS.find(x=>x.title==='Режим host network').id,'visual-23');
 assert.equal(DOCKER_VISUAL_TOPICS.find(x=>/Многоэтапная/.test(x.title)).id,'visual-12');
 assert.equal(new Set(DOCKER_VISUAL_TOPICS.map(x=>x.id)).size,DOCKER_VISUAL_TOPICS.length);
});

import {joinSpeechSentences} from '../src/speech-boundaries.js';
test('ASR line wrapping cannot split an unfinished sentence into another lesson',()=>{
 const rows=[{start:0,end:8,text:'A vulnerable library can compromise every container'},
 {start:8,end:12,text:'built from it.'},{start:12,end:20,text:'Now let us discuss multi-stage builds.'}];
 const units=joinSpeechSentences(rows);
 assert.equal(units.length,2);assert.equal(units[0].end,12);
 assert.equal(units[1].start,12);
 assert.equal(units[0].text,'A vulnerable library can compromise every container built from it.');
});

test('partial OCR cannot crop the visible end of a source command',()=>{
 const width=160,height=90,pixels=new Uint8ClampedArray(width*height*4).fill(255);
 for(let y=24;y<42;y++)for(let x=10;x<70;x++){
  const at=(y*width+x)*4;pixels[at]=pixels[at+1]=pixels[at+2]=0;
 }
 const lines=[{text:'FROM node',confidence:90,box:{x0:10,y0:24,x1:35,y1:30}},{text:'CMD node',confidence:90,box:{x0:10,y0:34,x1:35,y1:42}}];
 const scene=makeStoryboard({width,height,duration:30,pixels,lines});
 assert.ok(scene.panels[0].rect.x+scene.panels[0].rect.w>=70/width);
});

test('excluding a transcribed closing does not falsely report incomplete ASR',()=>{
 const rows=[{start:0,end:50,text:'Containers are isolated processes. For example each application has its own network and files, while the host kernel is shared.'},{start:50,end:99,text:'Thank you for your time.'}];
 const plan=planCompleteTopics(rows,100,{chapters:[{start:0,end:50,title:'Containers',key:'containers-vs-vm'},{start:50,end:100,title:'Closing',key:'outro'}]});
 assert.equal(plan.summary.incompleteTranscript,false);
});

test('a command crossing the center does not create a second panel of its tail',()=>{
 const width=160,height=90,pixels=new Uint8ClampedArray(width*height*4).fill(255);
 for(let y=24;y<60;y++)for(let x=8;x<106;x++){
  const at=(y*width+x)*4;pixels[at]=pixels[at+1]=pixels[at+2]=0;
 }
 const lines=[{text:'FROM node:20',confidence:90,box:{x0:8,y0:24,x1:55,y1:30}},
 {text:'RUN npm ci --omit=dev && npm cache clean --force',confidence:90,box:{x0:8,y0:48,x1:106,y1:60}}];
 const scene=makeStoryboard({width,height,duration:30,pixels,lines});
 assert.equal(scene.panels.length,1);
 assert.ok(scene.panels[0].rect.x+scene.panels[0].rect.w>=106/width);
});
