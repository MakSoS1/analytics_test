import test from 'node:test';import assert from 'node:assert/strict';
import {timelinePieces,timelineStats,timelineTimeAtFraction,amendClipBoundary} from '../src/source-timeline.js';
test('timeline explicitly shows source gaps discarded and selected excerpts',()=>{
 const pieces=timelinePieces([{id:'a',start:20,end:40},{id:'b',start:65,end:85}],100);
 assert.deepEqual(pieces.map(x=>x.kind),['skipped','clip','skipped','clip','skipped']);
 assert.equal(timelineStats([{id:'a',start:20,end:40},{id:'b',start:65,end:85}],100).percent,40);
});
test('overlapping edits count unique included time rather than double counting',()=>{
 const clips=[{id:'a',start:0,end:50},{id:'b',start:40,end:80}];
 assert.equal(timelineStats(clips,100).keptSeconds,80);
});
test('timeline drag invalidates stale video composition and pedagogical approval',()=>{
 const c={id:'a',title:'Topic',start:20,end:100,status:'approved',approvedAt:'today',scene:{version:2}};
 const out=amendClipBoundary(c,'start',25,180);
 assert.equal(out.start,25);assert.equal(out.status,'needs-review');assert.equal(out.scene,undefined);
 assert.equal(c.start,20);
});
test('source scrubbing bounded to valid media',()=>{
 assert.equal(timelineTimeAtFraction(2,100),100);
 assert.equal(timelineTimeAtFraction(-2,100),0);
});
