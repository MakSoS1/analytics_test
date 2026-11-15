import assert from 'node:assert/strict';

// Evidence validation only: it never creates transcript, project, auth or ASR state.
export function validateAsrSmoke(state){
 assert.equal(state.crossOriginIsolated,false,'Unexpected cross-origin isolation');
 assert.equal(state.sharedArrayBufferAvailable,false,'Unexpected SharedArrayBuffer exposure');
 assert.equal(state.processingSeen,true,'No ordinary UI processing phase was observed');
 assert.equal(state.phase,'results','The app did not complete analysis');
 assert.equal(state.saveEnabled,true,'Completed project is unavailable');
 assert.equal(state.cancelEnabled,false,'Analysis is still busy');
 assert.ok(Number.isFinite(state.duration)&&state.duration>=20&&state.duration<=30,'Unexpected diagnostic excerpt duration');
 const transcript=String(state.transcript||'').trim();
 const cuePattern=/^(\d{2,}):(\d{2}):(\d{2})[,.](\d{3})\s+-->\s+(\d{2,}):(\d{2}):(\d{2})[,.](\d{3})\s*$/gm;
 const cues=[...transcript.matchAll(cuePattern)];
 assert.ok(cues.length,'The completed UI has no generated SRT cues');
 const seconds=(match,offset)=>Number(match[offset])*3600+Number(match[offset+1])*60+Number(match[offset+2])+Number(match[offset+3])/1000;
 let lastSpeechEnd=0;
 for(const cue of cues){
  const start=seconds(cue,1),end=seconds(cue,5);
  assert.ok(start>=0&&end>start&&end<=state.duration+1,'Invalid generated cue timing');
  lastSpeechEnd=Math.max(lastSpeechEnd,end);
 }
 const speech=transcript.replace(cuePattern,'').replace(/^\s*\d+\s*$/gm,'').trim();
 const wordCount=speech.split(/\s+/).filter(word=>/\p{L}/u.test(word)).length;
 assert.ok(wordCount>=3,'The completed UI has no meaningful nonempty speech text');
 return {cueCount:cues.length,wordCount,lastSpeechEnd};
}
