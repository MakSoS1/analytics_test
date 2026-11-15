import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {openFile} from './crypto.mjs';

test('compact review encryption retains evidence and excludes every MP4 and per-frame scene dump',async()=>{
 const mod=await import('./package-review.mjs').catch(()=>null);
 assert.ok(mod,'The compact encrypted review packager is not implemented');
 const dir=await mkdtemp(join(tmpdir(),'examclips-review-test-'));
 try{
  const evidence=join(dir,'evidence'),artifact=join(dir,'artifact'),privateRoot=join(dir,'private');
  await mkdir(join(evidence,'case','retest-review','clip-001','frames'),{recursive:true});
  const files={'run.json':'{}','case/result.json':'{}','case/original-source.mp4':'original media',
   'case/clip-001.mp4':'output media','case/project.json':'{}','case/transcript.srt':'1\n00:00:00,000 --> 00:00:01,000\nSpeech\n',
   'case/retest-review/clip-001/frames/sample-000001.jpg':'image bytes',
   'case/retest-review/clip-001/frames/full-decode.log':'decode completed',
   'case/retest-review/clip-001/frames/scene-frame-scores.jsonl':'huge dump',
   'case/retest-review/clip-001/frames/scene-metadata.log':'huge dump'};
  for(const [name,data] of Object.entries(files))await writeFile(join(evidence,name),data);
  const keys=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  const context={purpose:'evidence',repository:'MakSoS1/analytics_test',branch:'qa/examclips-stand45-2026-11-15',runId:'123',runAttempt:'1',caseId:'case',artifactKind:'compact-review'};
  await mod.packageReview({evidence,artifact,privateRoot,publicKey:keys.publicKey,context});
  const meta=JSON.parse(await readFile(join(artifact,'review','review-encryption.json'),'utf8'));
  const zip=join(dir,'decrypted.zip');
  await openFile(join(artifact,'review','review.enc'),zip,meta,keys.privateKey,context);
  const names=JSON.parse(execFileSync('python3',['-c','import json,sys,zipfile;print(json.dumps(zipfile.ZipFile(sys.argv[1]).namelist()))',zip],{encoding:'utf8'}));
  assert.ok(names.includes('case/project.json'));
  assert.ok(names.includes('case/transcript.srt'));
  assert.ok(names.includes('case/retest-review/clip-001/frames/sample-000001.jpg'));
  assert.ok(names.includes('case/retest-review/clip-001/frames/full-decode.log'));
  assert.ok(names.every(name=>!name.endsWith('.mp4')&&!name.includes('scene-frame-scores')&&!name.includes('scene-metadata')));
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('compact review packaging rejects authentication material even though output would be encrypted',async()=>{
 const mod=await import('./package-review.mjs').catch(()=>null);
 assert.ok(mod,'The compact encrypted review packager is not implemented');
 const dir=await mkdtemp(join(tmpdir(),'examclips-review-auth-test-'));
 try{
  await mkdir(join(dir,'evidence'));
  await writeFile(join(dir,'evidence','credentials.json'),'{}');
  await assert.rejects(mod.packageReview({evidence:join(dir,'evidence'),artifact:join(dir,'artifact'),privateRoot:join(dir,'private'),publicKey:'unused',context:{}}),/authentication/i);
 }finally{await rm(dir,{recursive:true,force:true});}
});
