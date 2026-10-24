import test from 'node:test';import assert from 'node:assert/strict';
import {captionSequenceAt,captionWords} from '../src/caption-flow.js';
test('progressive caption reveals only spoken words, without future sentence',()=>{
 const c=[{start:10,end:14,text:'Docker запускает отдельные контейнеры быстро.'}];
 const first=captionSequenceAt(c,10.05);
 assert.equal(first.words.filter(w=>w.visible).length,1);
 assert.ok(!first.plain.includes('контейнеры'));
 const later=captionSequenceAt(c,13.8);
 assert.ok(later.plain.length>0);assert.ok(later.words.length<=4);
 assert.equal(captionSequenceAt(c,14.01),null);
});
test('real word timestamps win over interpolated SRT and preserve confidence flag',()=>{
 const c=[{start:0,end:2,text:'Один второй третий',words:[
  {start:0,end:.25},{start:.25,end:1.3},{start:1.3,end:2}]}];
 const q=captionSequenceAt(c,.75);
 assert.equal(q.words[q.activeIndex].text,'второй');assert.equal(q.precise,true);
});
test('timestamp-only subtitles honestly mark word timings as approximated',()=>{
 const q=captionSequenceAt([{start:0,end:4,text:'Распознавание работает локально'}],2);
 assert.equal(q.precise,false);assert.ok(q.words.length<=4);
});
test('long groups cycle without leaving all previous words on screen',()=>{
 const tokens='one two three four five six seven eight nine ten eleven twelve';
 const c=[{start:0,end:12,text:tokens}];
 const p=captionSequenceAt(c,0);
 const q=captionSequenceAt(c,9.8);
 assert.ok(p.words.length<=4&&q.words.length<=4);
 assert.ok(!q.plain.includes('one'));assert.equal(captionWords(tokens).length,12);
});
test('silence and invalid cues do not produce captions',()=>{
 assert.equal(captionSequenceAt([],10),null);
 assert.equal(captionSequenceAt([{start:0,end:0,text:'Wrong'}],0),null);
});
