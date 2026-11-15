// Preparation-only real-ASR gate; neither diagnostic attempt is a quality case.
import {chromium} from 'playwright';
import {mkdir,readFile,writeFile,copyFile,rm,stat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {startServer} from './stand-server.mjs';
import {digest} from './stand-bundle.mjs';
import {runAsrAttempt} from './stand-asr-attempt.mjs';
import {runRequiredGate} from './preparation-gate.mjs';

const HERE=dirname(fileURLToPath(import.meta.url));
const config=JSON.parse(await readFile(join(HERE,'stand-config.json'),'utf8'));
const manifest=JSON.parse(await readFile(join(HERE,'manifest.json'),'utf8'));
const sourceCase=manifest.cases.find(item=>item.id==='ru03');
assert.ok(sourceCase?.platform==='rutube'&&sourceCase.video_id==='8f99eedf6e3aa21d8f37ef07acf34567','Unexpected diagnostic source');
const EXPECTED_SOURCE_SHA256='f7628bb149c68d1563664067b213c7653993aa76ef1739fe8a91890c0525d422';
const SOURCE_START=20,EXCERPT_SECONDS=25;
if(!process.env.AUDIT_ROOT||!process.env.AUDIT_OUT)throw Error('Runner-private audit and evidence paths required');
const root=resolve(process.env.AUDIT_ROOT),fixture=join(root,'asr-smoke-source.mp4'),original=join(root,'asr-smoke-original.mp4');
const caseFile=join(root,'asr-smoke-source-request.json'),evidence=join(resolve(process.env.AUDIT_OUT),'bundle-prepare');
await mkdir(evidence,{recursive:true,mode:0o700});
const diagnostic=value=>String(value||'').replace(/https?:\/\/[^\s"'<>]+/g,value=>{try{const url=new URL(value);return url.origin+url.pathname}catch{return '[url]'}})
 .replace(/Bearer\s+[A-Za-z0-9._-]+/gi,'Bearer [redacted]').replace(/eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[token]').slice(0,3000);
const save=(name,value)=>writeFile(join(evidence,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
const bounded=(operation,milliseconds,label)=>new Promise((yes,no)=>{
 const timer=setTimeout(()=>no(Error(label+' timed out')),milliseconds);
 Promise.resolve(operation).then(value=>{clearTimeout(timer);yes(value)},error=>{clearTimeout(timer);no(error)});
});
async function command(executable,args,timeout){
 return new Promise((yes,no)=>{
  const child=spawn(executable,args,{stdio:['ignore','pipe','pipe'],detached:true});let stdout='',stderr='',settled=false;
  const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);error?no(error):yes(value)};
  child.stdout.on('data',data=>{if(stdout.length<524288)stdout+=data});
  child.stderr.on('data',data=>{if(stderr.length<65536)stderr+=data});
  child.on('error',error=>finish(Error(executable+' failed: '+diagnostic(error.message))));
  child.on('close',(code,signal)=>finish(code===0?null:Error(executable+' failed'+(signal?' ('+signal+')':'')+': '+diagnostic(stderr.slice(-2000))),stdout));
  const timer=setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL')}catch{}finish(Error(executable+' exceeded its diagnostic time budget'))},timeout);
 });
}
let stage='download_public_diagnostic_source',server;
const started=Date.now(),overallDeadline=started+16*60*1000;
const remaining=()=>Math.max(0,overallDeadline-Date.now());
const report={targetKind:'test_instance',scope:'preparation_real_asr_excerpt_only',sourceCommit:config.source_commit,
 artifactId:config.artifact_id,artifactSha256:config.artifact_sha256,qualityCase:false,matrixEligible:false};
try{
 await mkdir(root,{recursive:true,mode:0o700});await writeFile(caseFile,JSON.stringify(sourceCase)+'\n',{mode:0o600});
 await command('python3',[join(HERE,'download-source.py'),caseFile,original,join(evidence,'asr-smoke-original-source.json')],300000);
 report.originalSource=JSON.parse(await readFile(join(evidence,'asr-smoke-original-source.json'),'utf8'));
 assert.equal(report.originalSource.sha256,EXPECTED_SOURCE_SHA256,'The public smoke source differs from the verified RU03 source');
 stage='extract_diagnostic_excerpt';
 await command('ffmpeg',['-hide_banner','-loglevel','error','-nostdin','-y','-ss',String(SOURCE_START),'-i',original,
  '-t',String(EXCERPT_SECONDS),'-map','0:v:0','-map','0:a:0','-c:v','libx264','-preset','veryfast','-crf','23',
  '-pix_fmt','yuv420p','-c:a','aac','-b:a','128k','-movflags','+faststart',fixture],60000);
 const probe=JSON.parse(await command('ffprobe',['-v','error','-show_format','-show_streams','-of','json',fixture],15000));
 const duration=Number(probe.format.duration);assert.ok(Math.abs(duration-EXCERPT_SECONDS)<0.5,'Unexpected excerpt duration');
 assert.ok(['video','audio'].every(kind=>probe.streams.some(stream=>stream.codec_type===kind)),'Excerpt requires real video and audio');
 report.excerpt={sourceCaseId:'ru03',sourceStartSeconds:SOURCE_START,requestedSeconds:EXCERPT_SECONDS,durationSeconds:duration,
  bytes:(await stat(fixture)).size,sha256:await digest(fixture),evidenceFile:'asr-smoke-source.mp4',encryptedDiagnosticOnly:true};
 await copyFile(fixture,join(evidence,report.excerpt.evidenceFile));
 stage='start_verified_server';server=await startServer(join(root,'site'),config);
 const attempt=async(mode,totalBudgetMs)=>{
  assert.equal(await digest(fixture),report.excerpt.sha256,'The diagnostic source bytes changed between attempts');
  return runAsrAttempt({chromium,mode,root,evidence,fixture,excerpt:report.excerpt,overallDeadline,totalBudgetMs});
 };
 stage='required_persistent_asr';
 const outcome=await runRequiredGate({runPrimary:()=>attempt('persistent',Math.min(660000,remaining())),
  runControl:budget=>attempt('nonpersistent',budget),remaining});
 Object.assign(report,outcome.primary);
 report.scope='preparation_real_asr_excerpt_only';report.requiredGateFile='primary-asr-report.json';
 report.diagnosticControl=outcome.control;report.matrixEligible=outcome.releaseMatrix;
 report.status=outcome.releaseMatrix?'passed':'failed';report.totalSeconds=(Date.now()-started)/1000;
 await save('ui-smoke-report.json',report);
 if(outcome.control.status!=='not_run')console.log('STAND_ASR_CONTROL_RESULT '+JSON.stringify({scope:'diagnostic_only',status:outcome.control.status,
  matrixEligible:false,sourceSha256:report.excerpt.sha256,asr:outcome.control.asr||null,resourceObservations:outcome.control.resourceObservations||null}));
 if(outcome.releaseMatrix){
  console.log('STAND_UI_SMOKE_SUCCESS '+JSON.stringify({targetKind:report.targetKind,scope:report.scope,status:report.status,
   sourceCommit:report.sourceCommit,crossOriginIsolated:report.crossOriginIsolated,sharedArrayBufferAvailable:report.sharedArrayBufferAvailable,
   excerpt:report.excerpt,asr:report.asr,blockedRequests:report.deniedRequests.length,totalSeconds:report.totalSeconds,matrixEligible:true}));
 }else{
  console.error('STAND_UI_SMOKE_FAILED '+JSON.stringify({stage:report.stage,errorType:report.errorType,errorMessage:report.errorMessage,
   deniedRequests:report.deniedRequests,controlStatus:outcome.control.status,matrixEligible:false}));process.exitCode=1;
 }
}catch(error){
 report.status='failed';report.stage=stage;report.errorType=error.name;report.errorMessage=diagnostic(error.message);report.matrixEligible=false;
 report.totalSeconds=(Date.now()-started)/1000;report.diagnosticControl=report.diagnosticControl||{status:'not_run',reason:'preflight_or_orchestration_failure'};
 await save('ui-smoke-report.json',report).catch(()=>{});
 console.error('STAND_UI_SMOKE_FAILED '+JSON.stringify({stage,errorType:error.name,errorMessage:report.errorMessage,matrixEligible:false}));process.exitCode=1;
}finally{
 if(server){server.closeAllConnections();await bounded(new Promise(done=>server.close(done)),5000,'Server close').catch(()=>{})}
 await Promise.allSettled([fixture,original,caseFile].map(path=>rm(path,{force:true})));
}
