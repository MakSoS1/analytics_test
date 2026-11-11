import test from 'node:test';
import assert from 'node:assert/strict';
import {createPublicInputReader} from './public-input.mjs';

const prefix='.audit-recovery/123/1/root',path=prefix+'/request.json';
const base={repository:'MakSoS1/analytics_test',branch:'qa/examclips-audit-2026-11-11',prefix,token:'public-test-token'};
const json=(value,status=200,headers={})=>new Response(status===304?null:JSON.stringify(value),{status,headers});
test('fresh API command is observed when raw branch replica is stale',async()=>{
 const calls=[],read=createPublicInputReader({...base,fetchImpl:async(url,options)=>{
  calls.push({url,options});return json({sequence:url.startsWith('https://api.github.com/')?2:1},200,{etag:'"two"'});
 }});
 assert.equal((await read(path)).sequence,2);
 assert.equal(calls.length,1);assert.equal(calls[0].options.headers.Authorization,'Bearer public-test-token');
 assert.equal(calls[0].options.headers.Accept,'application/vnd.github.raw+json');
 assert.equal(calls[0].options.redirect,'error');
 assert.equal(new URL(calls[0].url).searchParams.get('ref'),base.branch);
 assert.equal(calls[0].url.includes('recoveryPoll'),false);
});
test('authenticated conditional 304 reuses immutable cached JSON and changed ETag updates it',async()=>{
 const requests=[],responses=[json({sequence:1},200,{etag:'"one"'}),json(null,304),json({sequence:2},200,{etag:'"two"'})];
 const read=createPublicInputReader({...base,fetchImpl:async(url,options)=>{requests.push(options);return responses.shift();}});
 const first=await read(path);first.sequence=99;
 assert.equal((await read(path)).sequence,1);
 assert.equal(requests[1].headers['If-None-Match'],'"one"');
 assert.equal((await read(path)).sequence,2);
 assert.equal(requests[2].headers['If-None-Match'],'"one"');
});
test('missing files use bounded negative polling and can subsequently appear',async()=>{
 let time=0,calls=0;
 const read=createPublicInputReader({...base,now:()=>time,fetchImpl:async()=>++calls===1?json({},404):json({sequence:1},200,{etag:'"one"'})});
 assert.equal(await read(path),null);time=10000;assert.equal(await read(path),null);assert.equal(calls,1);
 time=30000;assert.equal((await read(path)).sequence,1);assert.equal(calls,2);
});
test('paths cannot escape the exact current run lane handoff files',async()=>{
 let calls=0;const read=createPublicInputReader({...base,fetchImpl:async()=>{calls++;return json({});}});
 for(const invalid of ['.audit-recovery/123/1/en/request.json',prefix+'/../input.json',prefix+'/responses/00001.json','https://example.test/key'])
  await assert.rejects(()=>read(invalid),/PUBLIC_INPUT_PATH_ESCAPE/);
 assert.equal(calls,0);
});
test('304 without a validated cache fails closed',async()=>{
 const read=createPublicInputReader({...base,fetchImpl:async()=>json(null,304)});
 await assert.rejects(()=>read(path),/PUBLIC_READ_UNCACHED_304/);
});
test('UTF-8 input is decoded exactly and malformed UTF-8 is rejected',async()=>{
 const read=createPublicInputReader({...base,fetchImpl:async()=>json({text:'Русский Ελληνικά 🧪'},200,{etag:'"u"'})});
 assert.equal((await read(path)).text,'Русский Ελληνικά 🧪');
 const bad=createPublicInputReader({...base,fetchImpl:async()=>new Response(new Uint8Array([0xc0,0x80]))});
 await assert.rejects(()=>bad(path),/PUBLIC_INPUT_INVALID_UTF8/);
});
test('streamed oversized input cancels before parsing even without content-length',async()=>{
 let cancelled=false;
 const response=new Response(new ReadableStream({start(controller){controller.enqueue(new Uint8Array(17));},cancel(){cancelled=true;}}));
 const read=createPublicInputReader({...base,maxBytes:16,fetchImpl:async()=>response});
 await assert.rejects(()=>read(path),/PUBLIC_INPUT_TOO_LARGE/);assert.equal(cancelled,true);
});
test('declared oversized input is rejected without consuming body',async()=>{
 const read=createPublicInputReader({...base,maxBytes:16,fetchImpl:async()=>new Response('{}',{headers:{'content-length':'17'}})});
 await assert.rejects(()=>read(path),/PUBLIC_INPUT_TOO_LARGE/);
});
test('429 respects Retry-After without repeated calls or stale execution',async()=>{
 let time=0,calls=0;
 const read=createPublicInputReader({...base,now:()=>time,fetchImpl:async()=>++calls===1?json({},429,{'retry-after':'60'}):json({sequence:1},200,{etag:'"ok"'})});
 assert.equal(await read(path),null);time=59000;assert.equal(await read(path),null);assert.equal(calls,1);
 time=60000;assert.equal((await read(path)).sequence,1);
});
test('primary rate reset is honored without logging private request data',async()=>{
 let time=1000;const observations=[];
 const read=createPublicInputReader({...base,now:()=>time,onObservation:o=>observations.push(o),
  fetchImpl:async()=>json({},403,{'x-ratelimit-remaining':'0','x-ratelimit-reset':'100'})});
 assert.equal(await read(path),null);assert.equal(observations[0].retryAfterMs,100000);
 assert.equal(JSON.stringify(observations).includes(base.token),false);
});
test('temporary server failure retries and recovers after a bounded delay',async()=>{
 let time=0,calls=0;
 const read=createPublicInputReader({...base,now:()=>time,fetchImpl:async()=>++calls===1?json({},503):json({sequence:2},200,{etag:'"two"'})});
 assert.equal(await read(path),null);time=1000;assert.equal(await read(path),null);assert.equal(calls,1);
 time=2000;assert.equal((await read(path)).sequence,2);
});
test('unconditional responses fall back to slow polling to bound API allowance',async()=>{
 let time=0,calls=0;const read=createPublicInputReader({...base,now:()=>time,fetchImpl:async()=>{calls++;return json({sequence:1});}});
 assert.equal((await read(path)).sequence,1);time=5000;assert.equal(await read(path),null);assert.equal(calls,1);
 time=30000;assert.equal((await read(path)).sequence,1);assert.equal(calls,2);
});
test('invalid JSON, authorization errors, and redirects are explicit failures',async()=>{
 for(const [response,code] of [[new Response('{'),/PUBLIC_INPUT_INVALID_JSON/],[json({},401),/PUBLIC_READ_HTTP_401/],[json({},302),/PUBLIC_READ_HTTP_302/]]){
  const read=createPublicInputReader({...base,fetchImpl:async()=>response});
  await assert.rejects(()=>read(path),code);
 }
});
