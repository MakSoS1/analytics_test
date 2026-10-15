import test from 'node:test';import assert from 'node:assert/strict';
import {buildClips,normalizeChunks,validRange,parseSrt,toSrt,timecode,textAt} from '../src/segments.js';
test('boundary checks reject reversed and out of range',()=>{assert.ok(validRange(0,90,90));assert.ok(!validRange(10,9,100));assert.ok(!validRange(0,101,100))});
test('empty ASR produces editable fallback clip',()=>{const c=buildClips([],200);assert.equal(c.length,1);assert.deepEqual([c[0].start,c[0].end],[0,90])});
test('chunks are sorted/clipped and invalid removed',()=>{assert.deepEqual(normalizeChunks([{text:' B ',start:5,end:9},{text:'A',start:0,end:4},{text:' ',start:2,end:3},{text:'X',start:11,end:22}],12),[{text:'A',start:0,end:4},{text:'B',start:5,end:9},{text:'X',start:11,end:12}])});
test('segmentation respects max, sequence, coverage',()=>{
 const chunks=Array.from({length:20},(_,i)=>({start:i*30,end:i*30+30,text:'This is a complete topic. '+i+'.'}));
 const clips=buildClips(chunks,600);assert.ok(clips.length>=3);
 for(const c of clips)assert.ok(c.end-c.start<=180.001&&validRange(c.start,c.end,600));
 assert.equal(clips[0].start,0);assert.equal(clips.at(-1).end,600);
 for(let i=1;i<clips.length;i++)assert.equal(clips[i-1].end,clips[i].start);
});
test('subtitle round trip RU+EN with times',()=>{
 const original=[{start:3.25,end:5.5,text:'Пример Docker 🐳'},{start:6,end:7.5,text:'Hello world'}];
 const parsed=parseSrt(toSrt(original),60);
 assert.deepEqual(parsed,original);assert.equal(timecode(3661.007,true),'01:01:01,007');
 assert.equal(textAt(parsed,4),'Пример Docker 🐳');assert.equal(textAt(parsed,5.75),'');
});
test('invalid subtitle is not imported',()=>{assert.deepEqual(parseSrt('test',80),[]);assert.deepEqual(parseSrt('1\n00:00:20,000 --> 00:00:10,000\nWrong',80),[])});
