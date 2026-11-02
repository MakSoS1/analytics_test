import test from 'node:test';
import assert from 'node:assert/strict';
import {planGeneralTopics} from '../src/general-topics.js';
import {opener,closes,invitesQuestions,isFiller} from '../src/discourse-cues.js';
import {scoreAgainstReference} from '../src/topic-reference-score.js';
import {sourceSegments} from '../src/selective-stories.js';

// Builds a lecture from [text] lines spoken back to back, `seconds` each.
function lecture(lines,{seconds=10,start=0}={}){
 let t=start;
 return lines.map(text=>{const row={start:t,end:t+seconds-.5,text};t+=seconds;return row});
}
const body=(topic,n=8)=>Array.from({length:n},(_,i)=>
 `The ${topic} mechanism ${['regulates','changes','limits','explains','drives','balances','shapes','controls'][i%8]} the ${topic} process in observable ways ${i}.`);
const owner=(clips,time)=>clips.findIndex(c=>sourceSegments(c).some(s=>time>=s.start&&time<s.end));

test('discourse cues: openings, closings, question pauses and filler are told apart',()=>{
 assert.ok(opener("Now let's talk about inflation.")>=3);
 assert.ok(opener('And our third objective is performance.')>=3);
 assert.equal(opener("We'll speak about this example later."),0);
 assert.equal(opener('So, okay.'),0);
 assert.ok(closes('So, in summary, photosynthesis turns light into sugar.'));
 assert.ok(invitesQuestions('Do you have any questions?'));
 assert.ok(isFiller('Please write them in chat.'));
 assert.ok(isFiller("Okay, let's move to the next point."));
});

test('a topic summary stays with its topic; question pauses are not video content',()=>{
 const rows=lecture([
  "Let's talk about photosynthesis.",...body('photosynthesis'),
  'So, in summary, photosynthesis stores light energy as sugar.',
  'Do you have any questions?','Please write them in chat.','So, no questions.',"Okay, let's move to the next point.",
  "Now let's talk about respiration.",...body('respiration')]);
 const plan=planGeneralTopics(rows,rows.at(-1).end+1);
 assert.equal(plan.clips.length,2);
 const summary=rows.find(r=>/in summary/.test(r.text));
 assert.equal(owner(plan.clips,summary.start+1),0,'summary belongs to the first lesson');
 for(const filler of rows.filter(r=>/questions|chat|next point/i.test(r.text)))
  assert.equal(owner(plan.clips,filler.start+1),-1,'pause for questions is not rendered: '+filler.text);
 assert.match(plan.clips[1].title,/respiration/i);
});

test('items of an announced list are one lesson, not separate videos',()=>{
 const rows=lecture(["Let's talk about soil erosion.",'There are three reasons.',
  'First, rainfall.',...body('rainfall',3),'Second, wind.',...body('wind',3),'Third, farming.',...body('farming',3),
  "Now let's talk about river deltas.",...body('delta',10)]);
 const plan=planGeneralTopics(rows,rows.at(-1).end+1);
 assert.equal(plan.clips.length,2);
 assert.equal(owner(plan.clips,rows.find(r=>r.text==='Third, farming.').start+1),0);
});

test('an audience question joins the lesson it is about, from a later part of the lecture',()=>{
 const rows=lecture(["Let's talk about compound interest.",...body('interest',10),
  "Now let's talk about inflation.",...body('inflation',10),
  'Do you have any questions?','I have a question about compound interest.',
  'Does the interest mechanism also apply to monthly deposits?',
  'Yes, the interest mechanism regulates monthly deposits the same way, only the interest period changes.',
  'The interest process compounds each period, so monthly deposits grow faster.',
  'Thank you for a great question.']);
 const plan=planGeneralTopics(rows,rows.at(-1).end+1);
 assert.equal(plan.clips.length,2);
 const answer=rows.find(r=>/only the interest period/.test(r.text));
 assert.equal(owner(plan.clips,answer.start+1),0,'answer is attached to compound interest');
 assert.ok(sourceSegments(plan.clips[0]).length>=2,'assembled from two places');
 const seconds=plan.clips.flatMap(c=>sourceSegments(c));
 for(let i=0;i<seconds.length;i++)for(let j=i+1;j<seconds.length;j++)
  assert.ok(seconds[i].end<=seconds[j].start||seconds[j].end<=seconds[i].start,'no source second rendered twice');
});

test('welcome, biography and plan are dropped, a motivating story is kept',()=>{
 const rows=lecture(['Good evening, colleagues.','My name is Anna and I will be your guide.',
  'First, we will cover cells. Then we will look at tissues.','By the end of this lecture you will know both.',
  "But here's the truth, biology is chemistry with a history.",
  'Every organism you meet is a long chain of chemical accidents that worked.',
  'Every cell keeps that chemical history inside its membrane and its molecules.',
  'This history is why the same chemistry appears in yeast, in trees and in people.',
  'Understanding the shared chemistry makes every later biology topic easier to follow.',
  'Remember this chemical view because every later lecture will depend on it.',
  'Keep this picture of chemistry and history in mind for the whole semester.',
  "Now let's talk about cells.",...body('cell',10)]);
 const plan=planGeneralTopics(rows,700);
 for(const t of [0,10,20,30])assert.equal(owner(plan.clips,t+1),-1,'opening housekeeping at '+t);
 assert.ok(owner(plan.clips,41)>=0,'motivating story is kept');
});

test('a worked solution is not cut by length; an announced new topic ends it',()=>{
 const rows=lecture(["Let's solve this problem.",...body('equation',40),
  "Now let's talk about graphs.",...body('graph',8)],{seconds:15});
 const plan=planGeneralTopics(rows,rows.at(-1).end+1);
 assert.equal(plan.clips.length,2);
 assert.ok(plan.clips[0].end-plan.clips[0].start>600,'long solution kept whole');
});

test('reference scoring reports whole and focused topics',()=>{
 const clips=[{segments:[{start:0,end:100}],boundaryEvidence:{first:'Now photosynthesis.'}},
  {segments:[{start:100,end:300}],boundaryEvidence:{first:'Now respiration.'}}];
 const score=scoreAgainstReference(clips,{topics:[{title:'A',start:0,end:100,kind:'teaching'},
  {title:'B',start:100,end:200,kind:'teaching'},{title:'C',start:200,end:300,kind:'teaching'}]});
 assert.equal(score.summary.cleanTopics,1);
 assert.equal(score.summary.multiTopicClips,1);
 assert.equal(score.summary.startPrecision,1);
});
