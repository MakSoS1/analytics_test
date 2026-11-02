import test from 'node:test';import assert from 'node:assert/strict';
import {packWordEvents} from '../src/word-align.js';
import {captionSequenceAt} from '../src/caption-flow.js';
test('Whisper word timing survives phrase grouping as precise karaoke',()=>{
 const source=[
 {timestamp:[0,.32],text:'Вот'},{timestamp:[.4,.82],text:'Docker'},
 {timestamp:[.9,1.35],text:'контейнер.'},{timestamp:[2.1,2.5],text:'Далее'},
 {timestamp:[2.52,3],text:'продолжим'}];
 const segments=packWordEvents(source,10,40);
 assert.equal(segments.length,2);
 assert.equal(segments[0].words[1].start,10.4);
 const q=captionSequenceAt(segments,10.52);
 assert.equal(q.precise,true);assert.equal(q.words[q.activeIndex].text,'Docker');
});
test('invalid Whisper timestamps filtered with 30-second boundary clipping',()=>{
 const seg=packWordEvents([{timestamp:[1,2],text:'Hello'},{timestamp:[22,32],text:'world'},
  {timestamp:[null,null],text:'invalid'}],100,130);
 assert.equal(seg.length,2);assert.ok(seg.every(x=>x.end<=130));
});
test('fallback with empty word events creates no fabricated speech',()=>{
 assert.deepEqual(packWordEvents([],0,30),[]);
});
