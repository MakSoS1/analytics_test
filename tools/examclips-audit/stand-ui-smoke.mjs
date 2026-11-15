// Preparation-only real-ASR gate. This excerpt is never a 45-case quality result.
import {chromium} from 'playwright';
import {mkdir,readFile,writeFile,copyFile,rm,stat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {startServer} from './stand-server.mjs';
import {installNetworkPolicy,TARGET,ORIGIN} from './stand-policy.mjs';
import {digest} from './stand-bundle.mjs';
import {validateAsrSmoke} from './stand-smoke-checks.mjs';

const HERE=dirname(fileURLToPath(import.meta.url));
const config=JSON.parse(await readFile(join(HERE,'stand-config.json'),'utf8'));
const manifest=JSON.parse(await readFile(join(HERE,'manifest.json'),'utf8'));
const sourceCase=manifest.cases.find(item=>item.id==='ru03');
assert.ok(sourceCase?.platform==='rutube'&&sourceCase.video_id==='8f99eedf6e3aa21d8f37ef07acf34567','Unexpected diagnostic source');
const EXPECTED_SOURCE_SHA256='f7628bb149c68d1563664067b213c7653993aa76ef1739fe8a91890c0525d422';
const SOURCE_START=20,EXCERPT_SECONDS=25,ASR_BUDGET_MS=600000;
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
let stage='download_public_diagnostic_source',server,browser,page,processingSeen=false;
const denied=[],models=new Set(),events=[],progress=[],started=Date.now();
const report={targetKind:'test_instance',scope:'preparation_real_asr_excerpt_only',sourceCommit:config.source_commit,
 artifactId:config.artifact_id,artifactSha256:config.artifact_sha256,qualityCase:false};
async function snapshot(){
 return bounded(page.evaluate(()=>({phase:document.querySelector('#app')?.dataset.phase||null,
  status:document.querySelector('#progress')?.textContent||'',detail:document.querySelector('#processing-detail')?.textContent||'',
  stage:document.querySelector('#processing-title')?.textContent||'',
  cancelEnabled:!!document.querySelector('#cancel')&&!document.querySelector('#cancel').disabled,
  saveEnabled:!!document.querySelector('#save-project')&&!document.querySelector('#save-project').disabled})),20000,'UI snapshot');
}
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
 stage='launch_official_chrome';browser=await chromium.launch({channel:'chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const context=await browser.newContext({serviceWorkers:'block',viewport:{width:1440,height:1000}});
 await installNetworkPolicy(context,{denied,models});page=await context.newPage();page.setDefaultTimeout(20000);
 const event=entry=>{if(events.length<100)events.push({at:new Date().toISOString(),...entry})};
 page.on('pageerror',error=>event({type:'pageerror',message:diagnostic(error.message)}));
 page.on('console',message=>{if(['warning','error'].includes(message.type()))event({type:message.type(),message:diagnostic(message.text())})});
 page.on('requestfailed',request=>event({type:'requestfailed',url:diagnostic(request.url()),message:diagnostic(request.failure()?.errorText)}));
 stage='open_app';const navigation=await page.goto(TARGET,{waitUntil:'domcontentloaded',timeout:45000});await page.locator('#atlas-new-lecture').waitFor();
 const headers=await navigation.allHeaders();report.responseHeaders={csp:headers['content-security-policy']||null,coop:headers['cross-origin-opener-policy']||null,coep:headers['cross-origin-embedder-policy']||null};
 report.browser={version:browser.version(),...await page.evaluate(()=>({userAgent:navigator.userAgent,hardwareConcurrency:navigator.hardwareConcurrency}))};
 report.crossOriginIsolated=await page.evaluate(()=>crossOriginIsolated);assert.equal(report.crossOriginIsolated,false);
 report.sharedArrayBufferAvailable=await page.evaluate(()=>typeof SharedArrayBuffer!=='undefined');assert.equal(report.sharedArrayBufferAvailable,false);
 assert.equal(await page.locator('#auth-gate').isVisible().catch(()=>false),false);
 stage='ordinary_video_upload';await page.locator('#atlas-new-lecture').click();await page.locator('#video-file').setInputFiles(fixture);
 await page.waitForFunction(()=>document.querySelector('#wizard-next')&&!document.querySelector('#wizard-next').disabled,undefined,{timeout:45000});
 await page.locator('#wizard-next').click();stage='read_normal_settings';
 report.settings={language:await page.locator('#language').inputValue(),asrLimit:await page.locator('#asr-limit').inputValue(),
  outputQuality:await page.locator('#output-quality').inputValue(),ocrEngine:await page.locator('#ocr-engine').inputValue()};
 assert.equal(report.settings.language,'auto');assert.equal(report.settings.asrLimit,'all');assert.equal(report.settings.outputQuality,'standard');assert.equal(report.settings.ocrEngine,'auto');
 await page.locator('#wizard-next').click();await page.locator('#workflow-start').waitFor();assert.equal(await page.locator('#workflow-start').isEnabled(),true);
 await page.waitForFunction(()=>{const video=document.querySelector('#player');return video?.readyState>=2&&video.videoWidth>0},undefined,{timeout:20000});
 report.source=await page.locator('#player').evaluate(video=>({duration:video.duration,width:video.videoWidth,height:video.videoHeight,error:video.error?.code||null}));
 assert.ok(Math.abs(report.source.duration-duration)<0.5);assert.equal(report.source.error,null);
 stage='verify_no_backend';report.capabilities={};
 for(const path of ['/api/local-ocr-capabilities','/api/local-review-capabilities']){
  const response=await fetch(ORIGIN+path,{redirect:'error',signal:AbortSignal.timeout(3000)});assert.equal(response.status,404);report.capabilities[path]=response.status;
 }
 stage='ordinary_full_asr';assert.equal(denied.length,0);await page.locator('#workflow-start').click();
 const analysisAt=Date.now();let lastLog=0,lastProgress=0,completed=false;
 while(Date.now()-analysisAt<ASR_BUDGET_MS){
  assert.equal(denied.length,0,'A request escaped the approved network boundary');
  const state=await snapshot();if(state.phase==='processing')processingSeen=true;
  if(Date.now()-lastProgress>=10000||state.phase==='results'){
   if(progress.length<100)progress.push({elapsedSeconds:Math.round((Date.now()-analysisAt)/1000),...state,
    status:diagnostic(state.status),detail:diagnostic(state.detail),stage:diagnostic(state.stage)});lastProgress=Date.now();
  }
  if(state.phase==='results'&&state.saveEnabled&&!state.cancelEnabled){completed=true;break}
  if(/^Ошибка:/.test(state.status)&&!state.cancelEnabled)throw Error(diagnostic(state.status));
  if(Date.now()-analysisAt>12000&&!state.cancelEnabled&&!['processing','results'].includes(state.phase))throw Error('Real ASR did not start: '+diagnostic(state.status));
  if(Date.now()-lastLog>30000){console.log('STAND_ASR_SMOKE_PROGRESS '+JSON.stringify({elapsedSeconds:Math.round((Date.now()-analysisAt)/1000),phase:state.phase,processingSeen}));lastLog=Date.now()}
  await delay(2000);
 }
 assert.ok(completed,'Real ASR did not complete within 600 seconds');
 stage='verify_generated_transcript';await page.locator('.top-navigation [data-editor-tab="captions"]').click();
 const transcript=await page.locator('#transcript').inputValue(),state=await snapshot();
 report.asr={...validateAsrSmoke({...state,transcript,duration:report.source.duration,processingSeen,
  crossOriginIsolated:report.crossOriginIsolated,sharedArrayBufferAvailable:report.sharedArrayBufferAvailable}),
  processingSeen,completed:true,seconds:(Date.now()-analysisAt)/1000,transcriptFile:'asr-smoke-transcript.srt',
  transcriptSha256:createHash('sha256').update(transcript).digest('hex')};
 await writeFile(join(evidence,report.asr.transcriptFile),transcript,{mode:0o600});
 await page.screenshot({path:join(evidence,'asr-smoke-completed.png'),fullPage:false});
 assert.equal(denied.length,0);report.deniedRequests=denied;report.publicModelAssets=[...models];report.browserEvents=events;report.progress=progress;
 report.status='passed';report.totalSeconds=(Date.now()-started)/1000;await save('ui-smoke-report.json',report);
 console.log('STAND_UI_SMOKE_SUCCESS '+JSON.stringify({targetKind:report.targetKind,scope:report.scope,status:report.status,
  sourceCommit:report.sourceCommit,crossOriginIsolated:report.crossOriginIsolated,sharedArrayBufferAvailable:report.sharedArrayBufferAvailable,
  excerpt:report.excerpt,asr:report.asr,blockedRequests:denied.length,totalSeconds:report.totalSeconds}));
}catch(error){
 report.status='failed';report.stage=stage;report.errorType=error.name;report.errorMessage=diagnostic(error.message);report.deniedRequests=denied;
 report.browserEvents=events;report.progress=progress;report.processingSeen=processingSeen;report.totalSeconds=(Date.now()-started)/1000;
 if(page&&!page.isClosed()){
  try{report.lastUiState=await snapshot()}catch{}
  try{await page.screenshot({path:join(evidence,'ui-smoke-failure.png'),fullPage:false,timeout:5000,mask:[page.locator('#auth-gate'),page.locator('.billing-dialog')]});report.failureScreenshot='ui-smoke-failure.png'}catch{report.failureScreenshot=null}
 }
 await save('ui-smoke-report.json',report).catch(()=>{});
 console.error('STAND_UI_SMOKE_FAILED '+JSON.stringify({stage,errorType:error.name,errorMessage:report.errorMessage,deniedRequests:denied}));process.exitCode=1;
}finally{
 if(browser)await bounded(browser.close(),15000,'Browser close').catch(()=>{});
 if(server){server.closeAllConnections();await bounded(new Promise(done=>server.close(done)),5000,'Server close').catch(()=>{})}
 await Promise.allSettled([fixture,original,caseFile].map(path=>rm(path,{force:true})));
}
