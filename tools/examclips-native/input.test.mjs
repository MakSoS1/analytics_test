import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,stat,rm,utimes,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {seal} from './crypto.mjs';
let input={};
try{input=await import('./input.mjs')}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const identity={repository:'MakSoS1/analytics_test',branch:'qa/examclips-audit-2026-11-11',runId:'999123',runAttempt:'1',caseId:'rul01'};
const keys=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
function payload(){
  const project={schema:2,duration:7350.762,source:{name:'rul01.mp4',size:4096,modified:1794420000123,type:'video/mp4'},
    chunks:[{start:10,end:15,text:'This transcript is a synthetic test fixture.'}],
    clips:[{id:'retained-clip',start:10,end:4000,title:'Encrypted fixture title',segments:[{start:10,end:160},{start:800,end:975}],layout:'hybrid',status:'needs-review'}],selected:0,settings:{outputQuality:'standard'}};
  const bytes=Buffer.from(JSON.stringify(project,null,2)+'\n');
  return {version:1,suite:'native_export_probe',credentials:{email:'fixture@example.invalid',password:'fixture-secret-value-123'},
    origin:{runId:'43090979122',runAttempt:'1',caseId:'rul01',receiptSha256:'a'.repeat(64),projectPath:'rul01/clip-001-project-before-export.json',projectSha256:sha(bytes),artifactIds:['12345'],siteCommit:'5f14760735796fc58e330b3819944da1ab1865a3',
      assignmentStateSha256:'b'.repeat(64),assignmentRunId:'43090979122',assignmentRunAttempt:'1',assignmentCaseId:'rul01'},
    source:{url:'https://storage.teach-in.ru/video/f/d/fdiztn3bcj/sd.mp4',name:project.source.name,bytes:4096,modified:project.source.modified,sha256:sha(Buffer.alloc(4096,42)),durationSeconds:7350.762},
    projectBase64:bytes.toString('base64'),selectedClipId:'retained-clip'};
}
function changeProject(p,change){const project=JSON.parse(Buffer.from(p.projectBase64,'base64'));change(project);const b=Buffer.from(JSON.stringify(project));p.projectBase64=b.toString('base64');p.origin.projectSha256=sha(b);return p}

test('validates actual retained duration rather than the long source span',()=>{
  assert.equal(typeof input.validateInput,'function','strict native input validation is implemented');
  const valid=input.validateInput(payload(),identity);
  assert.equal(valid.outputSeconds,325);
  assert.equal(valid.clipIndex,0);
  assert.throws(()=>input.validateInput(changeProject(payload(),p=>p.clips[0].segments=[{start:10,end:160}]),identity),/CLIP_TOO_SHORT/);
});

test('rejects altered saved project bytes and a different case before any browser operation',()=>{
  assert.equal(typeof input.validateInput,'function');
  const altered=payload();altered.projectBase64=Buffer.from('{}').toString('base64');
  assert.throws(()=>input.validateInput(altered,identity),/PROJECT_HASH_MISMATCH/);
  assert.throws(()=>input.validateInput(payload(),{...identity,caseId:'enl01'}),/SOURCE_CASE_MISMATCH/);
  const assignedElsewhere=payload();assignedElsewhere.origin.assignmentRunId='43098721850';
  assert.throws(()=>input.validateInput(assignedElsewhere,identity),/PRIMARY_ASSIGNMENT_MISMATCH/);
});

test('rejects candidate/review-gated clips and traversal source names',()=>{
  assert.equal(typeof input.validateInput,'function');
  assert.throws(()=>input.validateInput(changeProject(payload(),p=>p.clips[0].candidate=true),identity),/CLIP_NOT_EXPORTABLE/);
  assert.throws(()=>input.validateInput(changeProject(payload(),p=>p.clips[0].editorialStatus='needs-more-context'),identity),/CLIP_NOT_EXPORTABLE/);
  const p=payload();p.source.name='../original.mp4';
  assert.throws(()=>input.validateInput(p,identity),/UNSAFE_SOURCE_NAME/);
});

test('compressed encrypted project/login round-trip keeps exact project bytes and rejects replay or tampering',()=>{
  assert.equal(typeof input.encodeInput,'function');assert.equal(typeof input.decodeInput,'function');
  const context={purpose:'native-input',...identity};
  const descriptor={version:1,context,publicKeyPem:keys.publicKey,keySha256:sha(keys.publicKey.trim()),expiresAt:new Date(Date.now()+60000).toISOString()};
  const p=payload(), envelope=input.encodeInput(p,descriptor);
  const publicBytes=JSON.stringify(envelope);
  for(const text of [p.credentials.password,p.credentials.email,'Encrypted fixture title'])assert.equal(publicBytes.includes(text),false);
  const restored=input.decodeInput(envelope,keys.privateKey,context);
  assert.equal(restored.projectBase64,p.projectBase64);assert.deepEqual(restored.credentials,p.credentials);
  assert.throws(()=>input.decodeInput(envelope,keys.privateKey,{...context,runId:'999124'}),/context|CONTEXT/i);
  const damaged=structuredClone(envelope),bytes=Buffer.from(damaged.ciphertext,'base64');bytes[4]^=1;damaged.ciphertext=bytes.toString('base64');
  assert.throws(()=>input.decodeInput(damaged,keys.privateKey,context));
});

test('source staging preserves exact bytes and millisecond mtime without mutating the input path',async()=>{
  assert.equal(typeof input.stageSource,'function');
  const root=await mkdtemp(join(tmpdir(),'native-source-test-'));
  try{
    const original=join(root,'authenticated-original.mp4'),content=Buffer.alloc(4096,42);await writeFile(original,content);
    await utimes(original,1700000000,1700000000);const before=await stat(original);
    const p=payload();const staged=await input.stageSource(original,join(root,'staged'),p.source);
    assert.equal(sha(await readFile(staged)),p.source.sha256);assert.equal((await stat(staged)).mtimeMs,p.source.modified);
    assert.equal((await stat(original)).mtimeMs,before.mtimeMs);assert.notEqual((await stat(staged)).ino,before.ino);
    await assert.rejects(()=>input.stageSource(original,join(root,'bad'),{...p.source,sha256:'0'.repeat(64)}),/SOURCE_HASH_MISMATCH/);
  }finally{await rm(root,{recursive:true,force:true})}
});

test('rejects an expired handoff and bounded gzip expansion',()=>{
  assert.equal(typeof input.encodeInput,'function');assert.equal(typeof input.decodeInput,'function');
  const context={purpose:'native-input',...identity};
  const descriptor={version:1,context,publicKeyPem:keys.publicKey,keySha256:sha(keys.publicKey.trim()),expiresAt:new Date(Date.now()-1000).toISOString()};
  assert.throws(()=>input.encodeInput(payload(),descriptor),/HANDOFF_EXPIRED/);
  const compressed=gzipSync(Buffer.alloc(16*1024*1024+1,32));
  assert.throws(()=>input.decodeInput(seal(compressed,keys.publicKey,context),keys.privateKey,context),/INPUT_TOO_LARGE/);
});

test('local handoff builder requires authenticated inventory hashes and a private credential file',async()=>{
  assert.equal(typeof input.buildInput,'function');
  const root=await mkdtemp(join(tmpdir(),'native-receipt-test-'));
  try{
    const p=payload(),caseDir=join(root,'evidence','rul01');await mkdir(caseDir,{recursive:true});
    const projectPath=join(caseDir,'clip-001-project-before-export.json');await writeFile(projectPath,Buffer.from(p.projectBase64,'base64'));
    await writeFile(join(caseDir,'original-source.mp4'),Buffer.alloc(4096,42));
    const sourceBytes=Buffer.from(JSON.stringify({duration_sec:p.source.durationSeconds}));await writeFile(join(caseDir,'source.json'),sourceBytes);
    const runBytes=Buffer.from(JSON.stringify({runId:p.origin.runId,caseId:'rul01',buildBefore:{data:{commit:p.origin.siteCommit}},buildAfter:{data:{commit:p.origin.siteCommit}}}));await writeFile(join(root,'evidence','run.json'),runBytes);
    const credentialPath=join(root,'input-login.json');await writeFile(credentialPath,JSON.stringify(p.credentials),{mode:0o600});
    const receipt={context:{purpose:'evidence',repository:identity.repository,branch:identity.branch,runId:p.origin.runId,runAttempt:'1',caseId:'rul01'},
      run_id:p.origin.runId,run_attempt:'1',case_id:'rul01',encrypted_context_verified:true,gcm_authenticated:true,case_directory:caseDir,
      artifacts:[{artifact_id:'12345'}],file_inventory:{
        [p.origin.projectPath]:{bytes:Buffer.from(p.projectBase64,'base64').length,sha256:p.origin.projectSha256},
        'rul01/original-source.mp4':{bytes:4096,sha256:p.source.sha256},
        'rul01/source.json':{bytes:sourceBytes.length,sha256:sha(sourceBytes)},'run.json':{bytes:runBytes.length,sha256:sha(runBytes)}}};
    const receiptPath=join(root,'receipt.json');await writeFile(receiptPath,JSON.stringify(receipt));
    const statePath=join(root,'state.json');await writeFile(statePath,JSON.stringify({primary_case_runs:{rul01:43090979122}}));
    const built=await input.buildInput(receiptPath,projectPath,p.selectedClipId,p.source.url,credentialPath,statePath);
    assert.equal(built.source.sha256,p.source.sha256);assert.equal(built.projectBase64,p.projectBase64);
    assert.equal(built.origin.siteCommit,p.origin.siteCommit);
    assert.equal(built.origin.assignmentRunId,p.origin.runId);
    await writeFile(statePath,JSON.stringify({primary_case_runs:{rul01:43098721850}}));
    await assert.rejects(()=>input.buildInput(receiptPath,projectPath,p.selectedClipId,p.source.url,credentialPath,statePath),/SELECTED_CASE_NOT_PRIMARY/);
    await writeFile(statePath,JSON.stringify({primary_case_runs:{rul01:43090979122}}));
    await writeFile(projectPath,'{}');await assert.rejects(()=>input.buildInput(receiptPath,projectPath,p.selectedClipId,p.source.url,credentialPath,statePath),/PROJECT_HASH_MISMATCH/);
    await writeFile(projectPath,Buffer.from(p.projectBase64,'base64'));receipt.gcm_authenticated=false;await writeFile(receiptPath,JSON.stringify(receipt));
    await assert.rejects(()=>input.buildInput(receiptPath,projectPath,p.selectedClipId,p.source.url,credentialPath,statePath),/UNAUTHENTICATED_RECEIPT/);
  }finally{await rm(root,{recursive:true,force:true})}
});
