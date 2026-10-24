import test from 'node:test';import assert from 'node:assert/strict';
import {evaluateTopics,approvedAnnotations} from '../src/topic-evaluation.js';
test('boundary metric perfect match on independent approved references',()=>{
 const a=[{start:0,end:120},{start:120,end:250}],b=[{start:2,end:119},{start:121,end:251}];
 const m=evaluateTopics(a,b);
 assert.equal(m.f1,1);assert.ok(m.meanBoundaryErrorSeconds<3);
});
test('missing references are rejected rather than claiming perfect accuracy',()=>assert.throws(()=>evaluateTopics([],[])));
test('too many spurious boundaries reduce precision',()=>{
 const m=evaluateTopics([{start:0,end:100},{start:100,end:150},{start:150,end:200}],
 [{start:0,end:200}],{tolerance:4});
 assert.ok(m.precision<1);
});
test('only manually approved lesson boundaries may be reference labels',()=>{
 const labels=approvedAnnotations({clips:[{start:0,end:90,status:'needs-review'},
 {start:90,end:200,status:'approved',approvedAt:'2026-10-16T10:00:00Z'}]});
 assert.equal(labels.length,1);assert.equal(labels[0].start,90);
});
