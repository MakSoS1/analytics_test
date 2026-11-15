import test from 'node:test';
import assert from 'node:assert/strict';

test('a successful diagnostic control cannot release the matrix after a failed required gate',async()=>{
 const {runRequiredGate}=await import('./preparation-gate.mjs');
 const calls=[];
 const result=await runRequiredGate({
  runPrimary:async()=>{calls.push('primary');return {status:'failed',asrStarted:true,browserClosed:true,errorMessage:'Failed to fetch'}},
  runControl:async budget=>{calls.push('control');assert.equal(budget,180000);return {status:'passed',asr:{cueCount:5}}},
  remaining:()=>600000});
 assert.deepEqual(calls,['primary','control']);assert.equal(result.releaseMatrix,false);
 assert.equal(result.primary.status,'failed');assert.equal(result.control.status,'passed');
});

test('the control runs only after an observed ASR failure with time for its full bounded budget',async()=>{
 const {runRequiredGate}=await import('./preparation-gate.mjs');let controls=0;
 const runControl=async()=>{controls++;throw Error('must not run')};
 const passed=await runRequiredGate({runPrimary:async()=>({status:'passed',asrStarted:true}),runControl,remaining:()=>600000});
 assert.equal(passed.releaseMatrix,true);assert.equal(passed.control.reason,'primary_passed');
 const early=await runRequiredGate({runPrimary:async()=>({status:'failed',asrStarted:false}),runControl,remaining:()=>600000});
 assert.equal(early.releaseMatrix,false);assert.equal(early.control.reason,'asr_not_started');
 const late=await runRequiredGate({runPrimary:async()=>({status:'failed',asrStarted:true,browserClosed:true}),runControl,remaining:()=>180000});
 assert.equal(late.releaseMatrix,false);assert.equal(late.control.reason,'insufficient_time');assert.equal(controls,0);
});

test('a diagnostic control exception preserves the required failure and bounded sanitized evidence',async()=>{
 const {runRequiredGate}=await import('./preparation-gate.mjs');
 const result=await runRequiredGate({runPrimary:async()=>({status:'failed',asrStarted:true,browserClosed:true}),
  runControl:async()=>{throw Error('secret-private-payload')},remaining:()=>600000});
 assert.equal(result.releaseMatrix,false);assert.equal(result.control.status,'failed');
 assert.equal(JSON.stringify(result).includes('secret-private-payload'),false);
});

test('a failed browser must close before a fresh control can observe runner resources',async()=>{
 const {runRequiredGate}=await import('./preparation-gate.mjs');let controlRan=false;
 const result=await runRequiredGate({runPrimary:async()=>({status:'failed',asrStarted:true,browserClosed:false}),
  runControl:async()=>{controlRan=true;return {status:'passed'}},remaining:()=>600000});
 assert.equal(result.releaseMatrix,false);assert.equal(controlRan,false);assert.equal(result.control.reason,'primary_browser_not_closed');
});
