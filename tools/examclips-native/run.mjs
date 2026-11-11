import {chromium} from 'playwright';
import {readFile,writeFile,mkdir,rm,rename,stat,lstat,statfs,appendFile} from 'node:fs/promises';
import {join,resolve,dirname,basename} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {freemem,totalmem,cpus,platform,release} from 'node:os';
import {setTimeout as delay} from 'node:timers/promises';
import {validateInput,fileHash,sha256} from './input.mjs';
import {verifyRestoredProject,classifyNativeStatus,expectedFrames} from './native-state.mjs';
import {identityFromEnv,safeError} from './native-context.mjs';

const HERE=dirname(fileURLToPath(import.meta.url)),identity=identityFromEnv();
const root=resolve(process.env.AUDIT_ROOT),output=resolve(process.env.AUDIT_OUT),dir=join(output,identity.caseId);
const ui=join(dir,'technical-ui'),now=()=>new Date().toISOString(),started=Date.now(),deadline=started+7200*1000;
await mkdir(root,{recursive:true,mode:0o700});await mkdir(dir,{recursive:true,mode:0o700});await mkdir(ui,{recursive:true,mode:0o700});
const run={schema:1,auditKind:'native_export_probe',supplementary:true,corpusCountIncrement:0,startedAt:now(),
  repository:identity.repository,runId:identity.runId,runAttempt:identity.runAttempt,caseId:identity.caseId,branch:identity.branch,
  sourceCommit:process.env.GITHUB_SHA||null,target:'https://examclips.dpdns.org/app/',
  scope:'One native streamed export from an authenticated existing long-lecture project; no new corpus source and no ASR rerun',
  runner:{platform:platform(),kernel:release(),cpu:cpus()[0]?.model,totalMemoryBytes:totalmem(),imageOS:process.env.ImageOS||null,imageVersion:process.env.ImageVersion||null},cases:[]};
const result={id:identity.caseId,auditKind:'native_export_probe',supplementary:true,corpusCountIncrement:0,startedAt:now(),status:'running',testStage:'validate_input',
  originalSourceEvidence:{status:'referenced_authenticated_primary_evidence'},storagePath:'native_file_system_access',asrUiInvoked:false,
  errors:[],warnings:[],clips:[],qualityVerdict:null,completionChecks:{sourceSha256Matched:false,retainedProjectPreserved:false,
    nativePickerObserved:false,nativeAPIUnchanged:false,appNativeCompletionObserved:false,noMP4DownloadEvent:false,outputFinalizedAndDecoded:false}};
run.cases.push(result);
let context,page,authenticated=false,heartbeat,heartbeatBusy=false,stopHeartbeat=false,pendingPersist=Promise.resolve(),lastLogged='';
const mp4Downloads=[],ownedCommands=new Set();
async function json(path,value){await writeFile(path,JSON.stringify(value,null,2)+'\n',{mode:0o600})}
function persist(){
  pendingPersist=pendingPersist.catch(()=>{}).then(async()=>{
    await json(join(root,'result-stage.json'),result);await rename(join(root,'result-stage.json'),join(dir,'result.json'));
    await json(join(root,'run-stage.json'),run);await rename(join(root,'run-stage.json'),join(output,'run.json'));
  });return pendingPersist;
}
async function bounded(promise,milliseconds,code){
  let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(code)),milliseconds)})])}finally{clearTimeout(timer)}
}
async function command(executable,args,milliseconds,code){
  return new Promise((resolvePromise,reject)=>{
    const child=spawn(executable,args,{stdio:['ignore','pipe','pipe'],detached:true});ownedCommands.add(child.pid);
    let stdout='',stderr='',settled=false;
    const finish=(error)=>{if(settled)return;settled=true;clearTimeout(timer);ownedCommands.delete(child.pid);error?reject(error):resolvePromise({stdout,stderr})};
    child.stdout.on('data',b=>{stdout=(stdout+b.toString()).slice(-(1024**2))});child.stderr.on('data',b=>{stderr=(stderr+b.toString()).slice(-8192)});
    child.on('error',()=>finish(Error(code)));child.on('close',status=>finish(status===0?null:Error(code)));
    const timer=setTimeout(()=>{
      try{process.kill(-child.pid,'SIGTERM')}catch{}
      setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL')}catch{}},2000).unref();finish(Error(code+'_TIMEOUT'));
    },Math.max(1000,milliseconds));
  });
}
async function build(){
  const response=await fetch('https://examclips.dpdns.org/site-build.json',{cache:'no-store',signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw Error('SITE_BUILD_UNAVAILABLE');return {checkedAt:now(),data:await response.json()};
}
async function snapshot(){
  if(!page||page.isClosed()||!authenticated)return null;
  return bounded(page.evaluate(()=>({phase:document.querySelector('#app')?.dataset.phase||null,
    status:(document.querySelector('#progress')?.textContent||'').slice(0,4000),detail:(document.querySelector('#processing-detail')?.textContent||'').slice(0,2000),
    exportEnabled:!!document.querySelector('#export')&&!document.querySelector('#export').disabled,
    saveEnabled:!!document.querySelector('#save-project')&&!document.querySelector('#save-project').disabled,
    jsHeapUsedBytes:performance.memory?.usedJSHeapSize||null})),30000,'BROWSER_SNAPSHOT_TIMEOUT');
}
async function resources(){
  const disk=await statfs(root);let available=freemem();
  try{const memory=await readFile('/proc/meminfo','utf8');available=Number(memory.match(/^MemAvailable:\s*(\d+)/m)?.[1]||available/1024)*1024}catch{}
  return {freeDiskBytes:disk.bavail*disk.bsize,availableMemoryBytes:available,nodeRssBytes:process.memoryUsage().rss};
}
async function observe(){
  if(heartbeatBusy||stopHeartbeat)return;heartbeatBusy=true;
  try{
    const state=await snapshot(),limits=await resources();
    const row={at:now(),elapsedSeconds:Math.round((Date.now()-started)/1000),testStage:result.testStage,...state,...limits};
    await appendFile(join(dir,'progress.jsonl'),JSON.stringify(row)+'\n');result.lastObservation=row;
    if(limits.freeDiskBytes<2*1024**3)result.resourceStop='DISK_RESERVE_REACHED';
    if(limits.availableMemoryBytes<512*1024**2)result.resourceStop='MEMORY_RESERVE_REACHED';
    const signature=result.testStage+':'+Math.floor(row.elapsedSeconds/30);
    if(signature!==lastLogged){console.log('NATIVE_PROGRESS '+JSON.stringify({caseId:identity.caseId,stage:result.testStage,elapsedSeconds:row.elapsedSeconds}));lastLogged=signature}
    await persist();
  }catch(error){result.lastObservationError=safeError(error)}finally{heartbeatBusy=false}
}
async function screenshot(name){
  if(!authenticated)return;
  await bounded(page.screenshot({path:join(ui,name),fullPage:false,mask:[page.locator('#auth-gate'),page.locator('.atlas-trial'),
    page.locator('.billing-dialog'),page.locator('.atlas-plans'),page.locator('#atlas-signout')]}),30000,'APP_SCREENSHOT_TIMEOUT');
}
async function closeDetail(){if(await page.locator('#microtopic-back').isVisible().catch(()=>false))await page.locator('#microtopic-back').click({timeout:10000})}
async function saveProject(name){
  await closeDetail();await page.locator('.top-navigation [data-editor-tab="export"]').click({timeout:10000});
  const pending=page.waitForEvent('download',{timeout:30000});pending.catch(()=>{});
  await page.locator('#save-project').click({timeout:10000});const download=await pending;
  if(await download.failure())throw Error('PROJECT_SNAPSHOT_DOWNLOAD_FAILED');
  const path=join(dir,name);await download.saveAs(path);await download.delete();
  try{return JSON.parse(await readFile(path,'utf8'))}catch{throw Error('PROJECT_SNAPSHOT_INVALID')}
}
async function selectClip(index){
  await closeDetail();await page.locator('.top-navigation [data-editor-tab="clip"]').click({timeout:10000});
  await page.locator('.microtopic-card[data-topic-index="'+index+'"] .microtopic-card-title').click({timeout:10000});
  await page.locator('#export').waitFor({state:'visible',timeout:10000});
  if(!await page.locator('#export').isEnabled())throw Error('SELECTED_EXPORT_DISABLED');
}
async function capabilities(){return page.evaluate(()=>({secureContext:isSecureContext,crossOriginIsolated,
  showSaveFilePicker:typeof window.showSaveFilePicker,showDirectoryPicker:typeof window.showDirectoryPicker,
  savePickerSource:typeof window.showSaveFilePicker==='function'?Function.prototype.toString.call(window.showSaveFilePicker):null,
  videoEncoder:typeof VideoEncoder,userAgent:navigator.userAgent}))}

await persist();
try{
  const credentialPath=process.env.NATIVE_CREDENTIALS_FILE,inputPath=process.env.NATIVE_INPUT_FILE,sourcePath=process.env.NATIVE_SOURCE_FILE;
  for(const path of [credentialPath,inputPath]){const st=await lstat(path);if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077))throw Error('PRIVATE_INPUT_REQUIRED')}
  let credentials,input;
  try{credentials=JSON.parse(await readFile(credentialPath,'utf8'));input=JSON.parse(await readFile(inputPath,'utf8'))}catch{throw Error('PRIVATE_INPUT_JSON_INVALID')}
  const validated=validateInput({...input,credentials},identity),sourceStat=await lstat(sourcePath);
  if(!sourceStat.isFile()||sourceStat.isSymbolicLink()||basename(sourcePath)!==input.source.name||sourceStat.size!==input.source.bytes||sourceStat.mtimeMs!==input.source.modified||await fileHash(sourcePath)!==input.source.sha256)
    throw Error('STAGED_SOURCE_IDENTITY_MISMATCH');
  result.source=JSON.parse(await readFile(join(dir,'source.json'),'utf8'));result.origin=input.origin;
  result.completionChecks.sourceSha256Matched=true;result.selectedClipId=input.selectedClipId;result.outputSeconds=validated.outputSeconds;
  await json(join(dir,'input-provenance.json'),{auditKind:'native_export_probe',origin:input.origin,source:input.source,selectedClipId:input.selectedClipId,
    projectSha256:input.origin.projectSha256,originalSourceStoredInPrimaryEvidence:true,corpusCountIncrement:0});
  const projectPath=join(root,'imported-project.json');await writeFile(projectPath,validated.projectBytes,{mode:0o600});
  await writeFile(join(dir,'project-input.json'),validated.projectBytes,{mode:0o600});
  run.buildBefore=await build();
  if(run.buildBefore.data.commit!==input.origin.siteCommit)throw Error('SITE_BUILD_CHANGED_FROM_PRIMARY');
  result.testStage='headed_browser_login';await persist();
  context=await chromium.launchPersistentContext(join(root,'browser-profile'),{channel:'chrome',headless:false,acceptDownloads:true,viewport:{width:1440,height:1000},
    args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-timer-throttling','--disable-renderer-backgrounding','--lang=en-US','--window-size=1460,1120','--no-first-run']});
  page=await context.newPage();
  // No initialization scripts, routes, native-API replacements, injected project
  // state, or file-handle substitutes are installed in this browser.
  await page.goto(run.target,{waitUntil:'domcontentloaded',timeout:60000});
  try{
    await page.locator('#auth-email').fill(credentials.email);await page.locator('#auth-password').fill(credentials.password);
    await page.locator('#auth-submit').click();await page.locator('#atlas-new-lecture').waitFor({timeout:60000});
  }catch{throw Error('REAL_SITE_AUTHENTICATION_FAILED')}
  finally{credentials=null;await rm(credentialPath,{force:true})}
  authenticated=true;result.authenticatedAt=now();run.browser=await capabilities();
  if(!run.browser.secureContext||run.browser.showSaveFilePicker!=='function'||!run.browser.savePickerSource?.includes('[native code]')||run.browser.videoEncoder!=='function')throw Error('NATIVE_BROWSER_CAPABILITY_UNAVAILABLE');
  page.on('download',download=>{if(/\.mp4$/i.test(download.suggestedFilename()))mp4Downloads.push({at:now(),filename:download.suggestedFilename()})});
  heartbeat=setInterval(()=>{observe().catch(()=>{})},5000);await observe();
  result.testStage='import_project_and_relink';await persist();
  // Standard app file controls consume real existing filesystem paths. Export
  // uses the separately observed, genuine native OS save dialog below.
  await page.locator('#project-file').setInputFiles(projectPath);
  await page.waitForFunction(()=>/Проект JSON открыт|Разметка открыта/.test(document.querySelector('#progress')?.textContent||''),{},{timeout:30000});
  await page.locator('#video-file').setInputFiles(sourcePath);
  const selectedFile=await page.locator('#video-file').evaluate(node=>{const f=node.files?.[0];return f?{name:f.name,size:f.size,lastModified:f.lastModified}:null});
  result.browserSelectedSource=selectedFile;
  if(!selectedFile||selectedFile.name!==input.source.name||selectedFile.size!==input.source.bytes||selectedFile.lastModified!==input.source.modified)throw Error('BROWSER_SOURCE_METADATA_MISMATCH');
  await page.waitForFunction(()=>!!document.querySelector('#save-project')&&!document.querySelector('#save-project').disabled&&
    /Восстановлены монтаж/.test(document.querySelector('#progress')?.textContent||''),{},{timeout:120000});
  const restored=await saveProject('project-imported.json');verifyRestoredProject(validated.project,restored,input.selectedClipId);
  const before=await saveProject('native-project-before-export.json'),selection=verifyRestoredProject(validated.project,before,input.selectedClipId);
  result.completionChecks.retainedProjectPreserved=true;
  result.clips=[{id:input.selectedClipId,index:selection.clipIndex,title:selection.clip.title,segments:selection.segments,outputSeconds:selection.outputSeconds,
    exportStatus:'not_run',storagePath:'native_file_system_access',titleTruth:'Requires viewing actual MP4 frames; this field is pre-export provenance'}];
  await selectClip(selection.clipIndex);await screenshot('04-imported-app.png');
  const windowSnapshot=join(root,'windows-before-export.json');
  await command('python3',[join(HERE,'native-dialog.py'),'snapshot','--output',windowSnapshot],30000,'X11_WINDOW_SNAPSHOT_FAILED');
  result.testStage='native_save_dialog';await persist();
  const target=join(dir,'native-clip.mp4'),dialogPromise=command('python3',[join(HERE,'native-dialog.py'),'operate','--before',windowSnapshot,'--target',target,
    '--case-dir',dir,'--evidence-dir',ui,'--timeout','90'],120000,'NATIVE_SAVE_DIALOG_FAILED');dialogPromise.catch(()=>{});
  await page.locator('#export').click({timeout:15000});await dialogPromise;
  result.nativeDialog=JSON.parse(await readFile(join(ui,'native-dialog.json'),'utf8'));
  result.completionChecks.nativePickerObserved=result.nativeDialog.status==='native_save_dialog_closed';
  result.testStage='native_stream_encoding';await persist();let observedComplete=false;
  while(Date.now()<deadline){
    if(result.resourceStop)throw Error(result.resourceStop);
    const state=await snapshot(),kind=classifyNativeStatus(state?.status||'');
    if(kind==='unexpected_asr')throw Error('UNEXPECTED_ASR_OPERATION');
    if(kind==='wrong_ram_path'||mp4Downloads.length)throw Error('RAM_EXPORT_PATH_OBSERVED');
    if(kind==='failed')throw Error('APP_EXPORT_REPORTED_FAILURE');
    if(kind==='native_complete'){result.nativeCompletionStatus=state.status;observedComplete=true;break}
    await delay(500);
  }
  if(!observedComplete)throw Error('NATIVE_EXPORT_TIME_BUDGET_EXCEEDED');
  result.completionChecks.appNativeCompletionObserved=true;
  const first=await stat(target);await delay(1000);const second=await stat(target);
  if(first.size<1024||first.size!==second.size||first.mtimeMs!==second.mtimeMs)throw Error('NATIVE_FILE_NOT_FINALIZED');
  const afterCapabilities=await capabilities();result.browserAfter=afterCapabilities;
  result.completionChecks.nativeAPIUnchanged=afterCapabilities.savePickerSource===run.browser.savePickerSource&&afterCapabilities.savePickerSource.includes('[native code]');
  result.completionChecks.noMP4DownloadEvent=mp4Downloads.length===0;result.mp4DownloadEvents=mp4Downloads;
  if(!result.completionChecks.nativeAPIUnchanged)throw Error('NATIVE_API_CHANGED_DURING_RUN');
  result.testStage='full_media_validation';await persist();
  const fps=before.settings?.outputQuality==='high'?30:15,frameCount=expectedFrames(selection.segments,fps);
  const report=join(dir,'native-media-validation.json');
  await command('python3',[join(HERE,'media_validation.py'),target,'--expected-seconds',String(selection.outputSeconds),'--expected-frames',String(frameCount),
    '--report',report,'--timeout',String(Math.max(60,Math.min(3600,(deadline-Date.now())/1000)))],Math.max(65000,Math.min(3660000,deadline-Date.now())),'NATIVE_MEDIA_VALIDATION_FAILED');
  const media=JSON.parse(await readFile(report,'utf8'));result.mediaValidation=media;
  result.completionChecks.outputFinalizedAndDecoded=media.full_decode_passed===true;
  Object.assign(result.clips[0],{file:'native-clip.mp4',bytes:media.bytes,sha256:media.sha256,exportStatus:'saved_native',videoDuration:media.video_duration,audioDuration:media.audio_duration});
  const after=await saveProject('native-project-after-export.json');verifyRestoredProject(validated.project,after,input.selectedClipId);
  await screenshot('05-native-export-completed-app.png');
  run.buildAfter=await build();run.buildChanged=run.buildAfter.data.commit!==run.buildBefore.data.commit;
  if(run.buildChanged)throw Error('SITE_BUILD_CHANGED_DURING_NATIVE_EXPORT');
  result.exportCounts={proposed:1,saved_native:1,downloaded:0};
  result.status='native_export_saved_and_decoded';result.testStage='finished';
}catch(error){
  result.status='native_export_probe_failed';result.errors.push({at:now(),stage:result.testStage,code:safeError(error)});
  if(result.clips[0]&&result.clips[0].exportStatus==='not_run')result.clips[0].exportStatus='failed';
  result.mp4DownloadEvents=mp4Downloads;
  if(authenticated)try{await screenshot('06-native-probe-failure-app.png')}catch{}
  process.exitCode=1;
}finally{
  stopHeartbeat=true;clearInterval(heartbeat);
  for(const pid of ownedCommands)try{process.kill(-pid,'SIGTERM')}catch{}
  if(context)try{await bounded(context.close(),15000,'BROWSER_CLOSE_TIMEOUT')}catch{result.warnings.push('Browser close exceeded its cleanup budget')}
  result.finishedAt=now();result.elapsedSeconds=(Date.now()-started)/1000;run.finishedAt=result.finishedAt;run.status=result.status;
  await persist();await pendingPersist;
  console.log('NATIVE_PROBE_SUMMARY '+JSON.stringify({caseId:identity.caseId,status:result.status,auditKind:'native_export_probe',corpusCountIncrement:0,
    completionChecks:result.completionChecks,failureCode:result.errors.at(-1)?.code||null}));
}
// Evidence is flushed before ending. Playwright owns the Chrome child and its
// process-exit cleanup; an unresponsive browser cannot hold this step forever.
process.exit(process.exitCode||0);
