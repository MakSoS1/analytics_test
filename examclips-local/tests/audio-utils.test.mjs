import test from 'node:test';import assert from 'node:assert/strict';
import {isSilent} from '../src/audio-utils.js';
test('exact silence does not reach Whisper',()=>assert.ok(isSilent(new Float32Array(16000))));
test('meaningful speech amplitude is retained',()=>{
 const samples=new Float32Array(16000);for(let i=0;i<samples.length;i++)samples[i]=0.08*Math.sin(2*Math.PI*260*i/16000);
 assert.equal(isSilent(samples),false);
});
test('no NaN crash in blank buffer',()=>assert.equal(isSilent(new Float32Array([NaN,0,0])),true));
