import {writeFile,stat} from 'node:fs/promises';
import {join,dirname,isAbsolute} from 'node:path';
import {tmpdir,platform,release,arch} from 'node:os';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {installNetworkPolicy,TARGET,ORIGIN} from './stand-policy.mjs';
import {validateAsrSmoke} from './stand-smoke-checks.mjs';
import {launchAuditBrowser,launchDiagnosticBrowser,browserLaunchSettings} from './browser-launch.mjs';
import {createResourceObserver,isMaterialBlobFailure} from './resource-observation.mjs';

const diagnostic=value=>String(value||'').replace(/https?:\/\/[^\s"'<>]+/g,value=>{try{const url=new URL(value);return url.origin+url.pathname}catch{return '[url]'}})
 .replace(/Bearer\s+[A-Za-z0-9._-]+/gi,'Bearer [redacted]').replace(/eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[token]').slice(0,3000);
const bounded=(operation,milliseconds,label)=>new Promise((yes,no)=>{
 const timer=setTimeout(()=>no(Error(label+' timed out')),Math.max(1,milliseconds));
 Promise.resolve(operation).then(value=>{clearTimeout(timer);yes(value)},error=>{clearTimeout(timer);no(error)});
});

// Both attempts use the same normal UI and immutable diagnostic fixture. Only browser context mode differs.
export async function runAsrAttempt({chromium,mode,root,evidence,fixture,excerpt,overallDeadline,totalBudgetMs}){
 assert.ok(['persistent','nonpersistent'].includes(mode));
 const label=mode==='persistent'?'primary':'control',started=Date.now(),deadline=Math.min(overallDeadline,started+totalBudgetMs);
 const remaining=()=>Math.max(0,deadline-Date.now());
 const timeout=maximum=>{if(remaining()<=0)throw Error('Diagnostic attempt deadline reached');return Math.max(1,Math.min(maximum,remaining()))};
 let stage='before_browser_launch',context,browser,closeBrowser,page,processingSeen=false,preparationSamples=0,lastResourceAt=0;
 let modelInfoEvents=0,errorSamples=0,blobSamples=0,blobOomSampled=false;
 const denied=[],models=new Set(),events=[],progress=[];
 const profile=join(root,label+'-browser-profile');
 const paths=[{role:mode==='persistent'?'persistent_browser_profile':'driver_managed_profile_parent_unverified',path:mode==='persistent'?profile:tmpdir()},
  {role:'os_tmpdir',path:tmpdir()},{role:'source_parent',path:dirname(fixture)},{role:'evidence_parent',path:evidence}];
 const resources=createResourceObserver({file:join(evidence,label+'-resource-observations.jsonl'),paths,maxSamples:20});
 const report={scope:mode==='persistent'?'required_persistent_asr_gate':'diagnostic_nonpersistent_control',qualityCase:false,
  mode,asrStarted:false,inputFixture:{...excerpt},runner:{platform:platform(),kernelRelease:release(),architecture:arch(),
   imageOS:process.env.ImageOS||null,imageVersion:process.env.ImageVersion||null}};
 const deadlineTimer=setTimeout(()=>{
  report.deadlineExceeded=true;
  if(closeBrowser)void bounded(closeBrowser(),15000,'Deadline browser close').catch(()=>{});
 },Math.max(1,remaining()));
 const event=entry=>{if(events.length<200)events.push({at:new Date().toISOString(),...entry})};
 async function snapshot(){
  return bounded(page.evaluate(()=>({phase:document.querySelector('#app')?.dataset.phase||null,
   status:document.querySelector('#progress')?.textContent||'',detail:document.querySelector('#processing-detail')?.textContent||'',
   stage:document.querySelector('#processing-title')?.textContent||'',
   cancelEnabled:!!document.querySelector('#cancel')&&!document.querySelector('#cancel').disabled,
   saveEnabled:!!document.querySelector('#save-project')&&!document.querySelector('#save-project').disabled})),timeout(20000),'UI snapshot');
 }
 try{
  assert.ok(remaining()>=30000,'Insufficient diagnostic time before browser launch');
  report.browserLaunch={mode,profileExistedBeforeLaunch:mode==='persistent'?await stat(profile).then(()=>true,error=>error.code==='ENOENT'?false:null):null,
   freshNonpersistentContext:mode==='nonpersistent',options:browserLaunchSettings()};
  await resources.observe('before_browser_launch');
  stage='launch_official_chrome';
  if(mode==='persistent'){context=await launchAuditBrowser(chromium,profile);closeBrowser=()=>context.close()}
  else{
   const launched=await launchDiagnosticBrowser(chromium);context=launched.context;browser=launched.browser;closeBrowser=launched.close;
   // Read only the driver-created profile path from our own browser, never retain the full command line.
   try{
    const session=await bounded(browser.newBrowserCDPSession(),timeout(3000),'Browser metadata session');
    try{
     const command=await bounded(session.send('Browser.getBrowserCommandLine'),timeout(3000),'Browser profile metadata');
     const argument=command.arguments?.find(value=>value.startsWith('--user-data-dir='));
     const actual=argument?.slice('--user-data-dir='.length);
     if(actual&&isAbsolute(actual)){paths[0]={role:'nonpersistent_browser_profile',path:actual};report.managedProfilePathObserved=true}
    }finally{await bounded(session.detach(),3000,'Browser metadata detach').catch(()=>{})}
   }catch(error){report.managedProfilePathObserved=false;report.managedProfileMetadataError=String(error.name||'Error')}
  }
  await installNetworkPolicy(context,{denied,models});page=await context.newPage();page.setDefaultTimeout(timeout(20000));
  page.on('pageerror',error=>{
   event({type:'pageerror',message:diagnostic(error.message)});
   if(errorSamples<2){errorSamples++;void resources.observe('page_error',{page,metadata:{eventType:'pageerror',errorText:diagnostic(error.message)}})}
  });
  page.on('console',message=>{
   const text=message.text();
   if(['warning','error'].includes(message.type()))event({type:message.type(),message:diagnostic(text)});
   else if(/\bHub\b|\bParakeet\b/i.test(text)&&modelInfoEvents<80){modelInfoEvents++;event({type:message.type(),scope:'model_info',message:diagnostic(text)})}
  });
  page.on('requestfailed',request=>{
   const url=request.url(),errorText=request.failure()?.errorText,isOom=/ERR_BLOB_OUT_OF_MEMORY/.test(errorText||'');
   event({type:'requestfailed',url:diagnostic(url),message:diagnostic(errorText)});
   if(isMaterialBlobFailure(url,errorText)&&((isOom&&!blobOomSampled)||blobSamples<2)){
    blobSamples++;if(isOom){blobOomSampled=true;report.firstBlobOom={at:new Date().toISOString(),url:diagnostic(url),errorText:diagnostic(errorText)}}
    void resources.observe('material_blob_failure',{page,metadata:{eventType:'requestfailed',blobUrl:diagnostic(url),errorText:diagnostic(errorText)}});
   }
  });
  stage='open_app';const navigation=await page.goto(TARGET,{waitUntil:'domcontentloaded',timeout:timeout(45000)});
  await page.locator('#atlas-new-lecture').waitFor({timeout:timeout(20000)});
  const headers=await navigation.allHeaders();report.responseHeaders={csp:headers['content-security-policy']||null,coop:headers['cross-origin-opener-policy']||null,coep:headers['cross-origin-embedder-policy']||null};
  report.browser={version:(browser||context.browser())?.version()||null,...await page.evaluate(()=>({userAgent:navigator.userAgent,hardwareConcurrency:navigator.hardwareConcurrency}))};
  if(!report.browser.version)report.browser.version=report.browser.userAgent.match(/Chrome\/([0-9.]+)/)?.[1]||null;
  report.crossOriginIsolated=await page.evaluate(()=>crossOriginIsolated);assert.equal(report.crossOriginIsolated,false);
  report.sharedArrayBufferAvailable=await page.evaluate(()=>typeof SharedArrayBuffer!=='undefined');assert.equal(report.sharedArrayBufferAvailable,false);
  assert.equal(await page.locator('#auth-gate').isVisible().catch(()=>false),false);
  await resources.observe('browser_ready',{page});
  stage='ordinary_video_upload';await page.locator('#atlas-new-lecture').click();await page.locator('#video-file').setInputFiles(fixture,{timeout:timeout(45000)});
  await page.waitForFunction(()=>document.querySelector('#wizard-next')&&!document.querySelector('#wizard-next').disabled,undefined,{timeout:timeout(45000)});
  await page.locator('#wizard-next').click();stage='read_normal_settings';
  report.settings={language:await page.locator('#language').inputValue(),asrLimit:await page.locator('#asr-limit').inputValue(),
   outputQuality:await page.locator('#output-quality').inputValue(),ocrEngine:await page.locator('#ocr-engine').inputValue()};
  assert.equal(report.settings.language,'auto');assert.equal(report.settings.asrLimit,'all');assert.equal(report.settings.outputQuality,'standard');assert.equal(report.settings.ocrEngine,'auto');
  await page.locator('#wizard-next').click();await page.locator('#workflow-start').waitFor();assert.equal(await page.locator('#workflow-start').isEnabled(),true);
  await page.waitForFunction(()=>{const video=document.querySelector('#player');return video?.readyState>=2&&video.videoWidth>0},undefined,{timeout:timeout(20000)});
  report.source=await page.locator('#player').evaluate(video=>({duration:video.duration,width:video.videoWidth,height:video.videoHeight,error:video.error?.code||null}));
  assert.ok(Math.abs(report.source.duration-excerpt.durationSeconds)<0.5);assert.equal(report.source.error,null);
  stage='verify_no_backend';report.capabilities={};
  for(const path of ['/api/local-ocr-capabilities','/api/local-review-capabilities']){
   const response=await fetch(ORIGIN+path,{redirect:'error',signal:AbortSignal.timeout(timeout(3000))});assert.equal(response.status,404);report.capabilities[path]=response.status;
  }
  await resources.observe('before_model_start',{page,metadata:{sourceBytes:excerpt.bytes,sourceSha256:excerpt.sha256,sourceDurationSeconds:excerpt.durationSeconds}});
  stage='ordinary_full_asr';assert.equal(denied.length,0);await page.locator('#workflow-start').click();report.asrStarted=true;
  const analysisAt=Date.now(),analysisDeadline=Math.min(deadline-20000,analysisAt+600000);let lastLog=0,lastProgress=0,completed=false;
  while(Date.now()<analysisDeadline){
   assert.equal(denied.length,0,'A request escaped the approved network boundary');
   const state=await snapshot();if(state.phase==='processing')processingSeen=true;
   if(state.phase==='processing'&&preparationSamples<6&&Date.now()-lastResourceAt>=10000){
    preparationSamples++;lastResourceAt=Date.now();void resources.observe('model_progress',{page,metadata:{phase:state.phase}});
   }
   if(Date.now()-lastProgress>=10000||state.phase==='results'){
    if(progress.length<100)progress.push({elapsedSeconds:Math.round((Date.now()-analysisAt)/1000),...state,
     status:diagnostic(state.status),detail:diagnostic(state.detail),stage:diagnostic(state.stage)});lastProgress=Date.now();
   }
   if(state.phase==='results'&&state.saveEnabled&&!state.cancelEnabled){completed=true;break}
   if(/^Ошибка:/.test(state.status)&&!state.cancelEnabled)throw Error(diagnostic(state.status));
   if(Date.now()-analysisAt>12000&&!state.cancelEnabled&&!['processing','results'].includes(state.phase))throw Error('Real ASR did not start: '+diagnostic(state.status));
   if(Date.now()-lastLog>30000){console.log('STAND_ASR_SMOKE_PROGRESS '+JSON.stringify({attempt:label,elapsedSeconds:Math.round((Date.now()-analysisAt)/1000),phase:state.phase,processingSeen}));lastLog=Date.now()}
   await delay(2000);
  }
  assert.ok(completed,'Real ASR did not complete within its bounded diagnostic budget');
  stage='verify_generated_transcript';await page.locator('.top-navigation [data-editor-tab="captions"]').click();
  const transcript=await page.locator('#transcript').inputValue(),state=await snapshot();
  report.asr={...validateAsrSmoke({...state,transcript,duration:report.source.duration,processingSeen,
   crossOriginIsolated:report.crossOriginIsolated,sharedArrayBufferAvailable:report.sharedArrayBufferAvailable}),
   processingSeen,completed:true,seconds:(Date.now()-analysisAt)/1000,transcriptFile:label+'-asr-transcript.srt',
   transcriptSha256:createHash('sha256').update(transcript).digest('hex')};
  await writeFile(join(evidence,report.asr.transcriptFile),transcript,{mode:0o600});
  await page.screenshot({path:join(evidence,label+'-asr-completed.png'),fullPage:false,timeout:timeout(5000)});
  assert.equal(denied.length,0);assert.ok(!report.deadlineExceeded,'Diagnostic attempt deadline reached');report.status='passed';
 }catch(error){
  report.status='failed';report.stage=stage;report.errorType=error.name;report.errorMessage=diagnostic(error.message);
  await resources.observe('attempt_failure',{page:page&&!page.isClosed()?page:undefined,metadata:{phase:stage,errorText:report.errorMessage}});
  if(page&&!page.isClosed()){
   try{report.lastUiState=await snapshot()}catch{}
   try{await page.screenshot({path:join(evidence,label+'-asr-failure.png'),fullPage:false,timeout:5000,mask:[page.locator('#auth-gate'),page.locator('.billing-dialog')]});report.failureScreenshot=label+'-asr-failure.png'}catch{report.failureScreenshot=null}
  }
 }finally{
  clearTimeout(deadlineTimer);
  await resources.observe('before_browser_cleanup',{page:page&&!page.isClosed()?page:undefined,metadata:{phase:stage}});
  await resources.flush();report.resourceObservations=resources.summary();
  report.deniedRequests=denied;report.publicModelAssets=[...models];report.browserEvents=events;report.progress=progress;
  report.processingSeen=processingSeen;report.totalSeconds=(Date.now()-started)/1000;report.modelInfoEvents=modelInfoEvents;report.modelInfoEventCap=80;
  report.browserClosed=false;
  if(closeBrowser)try{await bounded(closeBrowser(),15000,'Browser close');report.browserClosed=true}
  catch(error){report.browserCloseError=String(error.name||'Error')}
  await writeFile(join(evidence,label+'-asr-report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
 }
 return report;
}
