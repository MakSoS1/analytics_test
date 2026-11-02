import test from 'node:test';import assert from 'node:assert/strict';
import {normalizeCheckpoint,remainingWindows} from '../src/asr-checkpoint.js';
test('resume only missing 30-second windows, including silence-marked windows',()=>{
 assert.deepEqual(remainingWindows(96,Infinity,[0,60]),[30,90]);
 assert.deepEqual(remainingWindows(300,90,[0,30,60]),[]);
});
test('discard corrupt cache text and invalid windows',()=>{
 const a=normalizeCheckpoint({chunks:[{start:0,end:29,text:'lecture'},{start:30,end:300,text:'bad'},
 {start:-1,end:15,text:'bad'},{start:0,end:10,text:0}],completedWindows:[30,30,-30,34,300,0]},100);
 assert.deepEqual(a.completedWindows,[0,30]);
 assert.deepEqual(a.chunks,[{start:0,end:29,text:'lecture'}]);
});
test('empty transcript may still mark processed silence',()=>{
 const checkpoint=normalizeCheckpoint({chunks:[],completedWindows:[0,30,60]},80);
 assert.deepEqual(remainingWindows(80,80,checkpoint.completedWindows),[]);
});
