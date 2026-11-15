import test from 'node:test';
import assert from 'node:assert/strict';
import {validateAsrSmoke} from './stand-smoke-checks.mjs';

const complete={crossOriginIsolated:false,sharedArrayBufferAvailable:false,processingSeen:true,phase:'results',saveEnabled:true,cancelEnabled:false,
 transcript:'1\n00:00:00,000 --> 00:00:04,200\nA real spoken sentence.\n\n2\n00:00:04,200 --> 00:00:22,000\nThe second complete speech segment.\n',duration:25};
test('the ASR gate accepts completed real-text UI evidence, with the hosted single-thread exposure',()=>{
 assert.deepEqual(validateAsrSmoke(complete),{cueCount:2,wordCount:9,lastSpeechEnd:22});
});
test('the ASR gate rejects upload-only, busy, unobserved, or isolated runtime states',()=>{
 for(const patch of [{phase:'configure'},{cancelEnabled:true},{saveEnabled:false},{processingSeen:false},{crossOriginIsolated:true},{sharedArrayBufferAvailable:true}])
  assert.throws(()=>validateAsrSmoke({...complete,...patch}));
});
test('the ASR gate requires speech and valid complete-source cue timing',()=>{
 for(const transcript of ['', '1\n00:00:00,000 --> 00:00:20,000\n', '1\n00:00:00,000 --> 00:00:30,000\nThis extends beyond the source.\n', '1\n00:00:20,000 --> 00:00:10,000\nThese timestamps are reversed.\n'])
  assert.throws(()=>validateAsrSmoke({...complete,transcript}));
});
