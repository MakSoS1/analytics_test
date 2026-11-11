import {chromium} from 'playwright';
import {mkdir,readFile,writeFile,appendFile,rm,stat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {arch,availableParallelism,cpus,platform,release,totalmem,version as osVersion} from 'node:os';
import {setTimeout as delay} from 'node:timers/promises';

const HERE=dirname(fileURLToPath(import.meta.url));
const require=createRequire(import.meta.url);
const config=JSON.parse(await readFile(join(HERE,'run-config.json'),'utf8'));
const manifest=JSON.parse(await readFile(join(HERE,'manifest.json'),'utf8'));
const root=resolve(process.env.AUDIT_ROOT||'audit-private');
const output=resolve(process.env.AUDIT_OUT||'audit-evidence');
if(config.production_url!=='https://examclips.dpdns.org/app/')throw Error('Audit target must remain the authorized production site');
if(config.export_policy!=='all')throw Error('This audit requires all default clips, without shortening them');
if(!Array.isArray(config.case_ids)||!config.case_ids.length||config.case_ids.length>6)throw Error('Select one to six sequential cases per runner');
if(new Set(config.case_ids).size!==config.case_ids.length)throw Error('Duplicate selected case ID');
const cases=config.case_ids.map(id=>{
  if(!/^[a-z0-9_-]+$/i.test(id))throw Error('Unsafe case ID');
  const item=manifest.cases.find(item=>item.id===id);
  if(!item)throw Error('Selected case is absent from manifest: '+id);
  if(!['ru','en','auto'].includes(item.language||'auto'))throw Error('Unsupported language selection');
  return item;
});
if(!(config.case_budget_seconds>0&&config.case_budget_seconds<=5400))throw Error('Case budget must be positive and at most 90 minutes');
if(config.case_budget_seconds*cases.length>270*60)throw Error('Selected sequential cases exceed the 270-minute runner processing budget');
await mkdir(root,{recursive:true,mode:0o700});await mkdir(output,{recursive:true,mode:0o700});
const json=(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n',{mode:0o600});
const now=()=>new Date().toISOString();
const safe=value=>String(value??'')
  .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,'[email]')
  .replace(/Bearer\s+[A-Za-z0-9._-]+/gi,'Bearer [redacted]')
  .replace(/eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[token]')
  .replace(/https?:\/\/[^\s"'<>]+/g,text=>{try{const u=new URL(text);return u.origin+u.pathname}catch{return '[url]'}})
  .slice(0,5000);
const remaining=deadline=>Math.max(0,deadline-Date.now());

async function command(executable,args,timeout=60000) {
  return new Promise((resolvePromise,reject)=>{
    const child=spawn(executable,args,{stdio:['ignore','pipe','pipe'],detached:true});
    let stdout='',stderr='',settled=false,killTimer;
    const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolvePromise(result)};
    child.stdout.on('data',data=>{if(stdout.length<4e6)stdout+=data});
    child.stderr.on('data',data=>{if(stderr.length<1e6)stderr+=data});
    child.on('error',error=>finish(error));
    child.on('close',code=>{clearTimeout(killTimer);finish(code===0?null:Error(executable+' failed: '+safe(stderr.slice(-3000))),{stdout,stderr})});
    const timer=setTimeout(()=>{
      try{process.kill(-child.pid,'SIGTERM')}catch{}
      killTimer=setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL')}catch{}},2000);
      finish(Error(executable+' exceeded its time budget'));
    },Math.max(1000,timeout));
  });
}
async function buildMetadata() {
  try{
    const response=await fetch('https://examclips.dpdns.org/site-build.json',{cache:'no-store',signal:AbortSignal.timeout(15000)});
    if(!response.ok)throw Error('HTTP '+response.status);
    return {checkedAt:now(),data:await response.json()};
  }catch(error){return {checkedAt:now(),error:safe(error.message)}}
}
const commitOf=build=>build?.data?.commit||build?.data?.sourceCommit||build?.data?.source_commit||null;
const runnerCpus=cpus();
const run={schema:1,startedAt:now(),repository:process.env.GITHUB_REPOSITORY,runId:process.env.GITHUB_RUN_ID,
  runAttempt:process.env.GITHUB_RUN_ATTEMPT,sourceCommit:process.env.GITHUB_SHA,
  target:config.production_url,selectedCases:config.case_ids,exportPolicy:'all',
  accommodation:config.disable_native_save_pickers?
    'Only showSaveFilePicker and showDirectoryPicker are unavailable in this CI browser. The unchanged app uses its existing full-MP4 memory/download fallback. The source input, real authentication, quota checks, ASR, models, topic planner and renderer are unchanged.':
    'No file-picker accommodation',
  playwrightVersion:require('playwright/package.json').version,node:process.version,
  runner:{platform:platform(),kernelRelease:release(),osVersion:osVersion(),architecture:arch(),
    imageOS:process.env.ImageOS||null,imageVersion:process.env.ImageVersion||null,
    cpuModel:runnerCpus[0]?.model||null,logicalCpuCount:runnerCpus.length,
    availableParallelism:availableParallelism(),totalMemoryBytes:totalmem()},cases:[]};
run.buildBefore=await buildMetadata();
await json(join(output,'run.json'),run);
await json(join(output,'selected-manifest.json'),{version:manifest.version,cases});
let context;
let fatal=null;

async function cleanScreenshot(page,path) {
  await page.screenshot({path,fullPage:true,mask:[
    page.locator('#auth-gate'),page.locator('.atlas-trial'),page.locator('.billing-dialog'),
    page.locator('.atlas-plans'),page.locator('#atlas-signout')
  ]});
}
async function closeDetail(page) {
  if(await page.locator('#microtopic-back').isVisible().catch(()=>false))await page.locator('#microtopic-back').click({timeout:5000});
}
async function uiDownload(page,selector,path,timeout) {
  const event=page.waitForEvent('download',{timeout:Math.max(1000,timeout)});event.catch(()=>{});
  await page.locator(selector).click({timeout:10000});
  const download=await event;
  const failure=await download.failure();
  if(failure)throw Error('Browser download failed: '+safe(failure));
  await download.saveAs(path);
}
async function saveProject(page,dir,name='project.json') {
  await closeDetail(page);
  await page.locator('.top-navigation [data-editor-tab="export"]').click({timeout:10000});
  const path=join(dir,name);
  await uiDownload(page,'#save-project',path,30000);
  return JSON.parse(await readFile(path,'utf8'));
}
function clipRows(project) {
  return project.clips.map((clip,index)=>{
    const segments=Array.isArray(clip.segments)&&clip.segments.length?clip.segments:[{start:clip.start,end:clip.end}];
    return {index,id:String(clip.id||index),title:clip.title,start:clip.start,end:clip.end,segments,
      outputSeconds:segments.reduce((total,piece)=>total+Math.max(0,piece.end-piece.start),0),
      candidate:!!clip.candidate,editorialStatus:clip.editorialStatus,status:clip.status,
      reviewReasons:clip.reviewReasons||[],exportStatus:'not_run',exportReason:'Not reached yet'};
  }).filter(clip=>clip.id!=='draft-1');
}
async function runCase(item) {
  const dir=join(output,item.id),mediaPath=join(root,'media',item.id+'.mp4'),caseFile=join(root,item.id+'.source-request.json');
  await mkdir(dir,{recursive:true});
  const started=Date.now(),deadline=started+config.case_budget_seconds*1000;
  const result={id:item.id,title:item.title,source_url:item.source_url,startedAt:now(),status:'running',
    timings:{},errors:[],warnings:[],clips:[],accommodation:run.accommodation};
  run.cases.push(result);
  await json(join(dir,'result.json'),result);
  console.log('CASE_START '+JSON.stringify({id:item.id,at:now()}));
  let page,project,lastStatus='',lastLog=0,lastPhase='',asrSeconds=0,asrTotal=0,cachedAsr=false,cameraReady=false,processingSeen=false,finishedAsr=false;
  let stopPolling=false;
  let polling;
  const events=[];
  const persist=()=>json(join(dir,'result.json'),result);
  async function snapshot() {
    if(!page||page.isClosed())return null;
    return page.evaluate(()=>({
      phase:document.querySelector('#app')?.dataset.phase||null,
      status:document.querySelector('#progress')?.textContent||'',
      detail:document.querySelector('#processing-detail')?.textContent||'',
      stage:document.querySelector('#processing-title')?.textContent||'',
      cancelEnabled:!!document.querySelector('#cancel')&&!document.querySelector('#cancel').disabled,
      saveEnabled:!!document.querySelector('#save-project')&&!document.querySelector('#save-project').disabled,
      topicCount:document.querySelectorAll('.microtopic-card').length
    }));
  }
  async function recordSnapshot() {
    const state=await snapshot();if(!state)return state;
    const message=state.status+' '+state.detail;
    const match=message.match(/Распознавание:\s*(\d+)\s*\/\s*(\d+)\s*с/);
    if(match){asrSeconds=Math.max(asrSeconds,Number(match[1]));asrTotal=Math.max(asrTotal,Number(match[2]));}
    if(/Все запрошенные аудиоокна уже распознаны/.test(message))cachedAsr=true;
    if(/Виртуальная камера готова:|Камера готова:/.test(message))cameraReady=true;
    if(state.phase==='processing')processingSeen=true;
    if(/Распознано \d+ реплик/.test(message))finishedAsr=true;
    if(state.status!==lastStatus||state.phase!==lastPhase){
      const row={at:now(),elapsedSeconds:Math.round((Date.now()-started)/1000),...state,status:safe(state.status),detail:safe(state.detail)};
      await appendFile(join(dir,'progress.jsonl'),JSON.stringify(row)+'\n');
      if(/^Ошибка:|^Остановлено:/.test(state.status))result.errors.push({phase:state.phase,message:safe(state.status)});
      lastStatus=state.status;lastPhase=state.phase;
    }
    if(Date.now()-lastLog>30000){
      console.log('CASE_PROGRESS '+JSON.stringify({id:item.id,elapsedSeconds:Math.round((Date.now()-started)/1000),phase:state.phase,asrSeconds,asrTotal,topicCount:state.topicCount}));
      lastLog=Date.now();
    }
    return state;
  }
  try {
    await json(caseFile,item);
    const downloadAt=Date.now();
    await command('python3',[join(HERE,'download-source.py'),caseFile,mediaPath,join(dir,'source.json')],Math.min(15*60*1000,remaining(deadline)));
    result.timings.downloadSeconds=(Date.now()-downloadAt)/1000;
    const source=JSON.parse(await readFile(join(dir,'source.json'),'utf8'));
    result.source=source;
    page=await context.newPage();page.setDefaultTimeout(15000);
    page.on('pageerror',error=>events.push({at:now(),type:'pageerror',message:safe(error.message)}));
    page.on('console',message=>{if(['warning','error'].includes(message.type()))events.push({at:now(),type:message.type(),message:safe(message.text())})});
    page.on('requestfailed',request=>{
      if(/\/auth\/|\/billing-api\//.test(request.url()))return;
      events.push({at:now(),type:'requestfailed',url:safe(request.url()),error:safe(request.failure()?.errorText)});
    });
    page.on('response',response=>{
      if(response.status()<400||/\/auth\/|\/billing-api\//.test(response.url()))return;
      events.push({at:now(),type:'http',url:safe(response.url()),status:response.status(),
        expected:/\/api\/local-(ocr|review)/.test(response.url())&&response.status()===404});
    });
    await page.goto(config.production_url,{waitUntil:'domcontentloaded',timeout:60000});
    await page.locator('#app').waitFor({timeout:30000});
    if(!await page.locator('#atlas-new-lecture').isVisible())
      await page.getByRole('button',{name:'ExamClips — мои лекции',exact:true}).click({timeout:15000});
    await page.locator('#atlas-new-lecture').waitFor({timeout:30000});
    await page.locator('#atlas-new-lecture').click();
    await page.locator('#video-file').setInputFiles(mediaPath,{timeout:60000});
    await page.waitForFunction(()=>document.querySelector('#wizard-next')&&!document.querySelector('#wizard-next').disabled,undefined,{timeout:60000});
    await page.locator('#wizard-next').click();
    result.observedSettings={language:await page.locator('#language').inputValue(),
      asrLimit:await page.locator('#asr-limit').inputValue(),
      outputQuality:await page.locator('#output-quality').inputValue(),
      sourceReferenceLanguage:item.language||'auto'};
    if(result.observedSettings.language!=='auto')throw Error('The site did not retain its automatic language default');
    if(await page.locator('#asr-limit').inputValue()!=='all')throw Error('The site did not default to full ASR');
    await page.locator('#wizard-next').click();
    await cleanScreenshot(page,join(dir,'01-confirmation.png'));
    const analysisAt=Date.now();
    await page.locator('#workflow-start').click();
    polling=(async()=>{while(!stopPolling){await recordSnapshot().catch(()=>{});await delay(2000);}})();
    while(remaining(deadline)>0) {
      const state=await recordSnapshot();
      if(state.phase==='results'&&state.saveEnabled&&!state.cancelEnabled)break;
      if(/^Ошибка:/.test(state.status)&&!state.cancelEnabled)throw Error(safe(state.status));
      if(Date.now()-analysisAt>12000&&!state.cancelEnabled&&state.phase!=='processing'&&state.phase!=='results')
        throw Error('Processing did not start: '+safe(state.status));
      await delay(2000);
    }
    if(!remaining(deadline))throw Error('Source exceeded its '+config.case_budget_seconds/60+'-minute budget during analysis');
    result.timings.analysisSeconds=(Date.now()-analysisAt)/1000;
    result.asr={processingSeen,maxSourceSecondsObserved:asrSeconds,totalSourceSecondsObserved:asrTotal,cachedAsr,completionMessageObserved:finishedAsr};
    const bgAt=Date.now(),bgEnd=Math.min(deadline-60000,Date.now()+config.background_wait_seconds*1000);
    while(Date.now()<bgEnd&&!cameraReady) {
      const state=await recordSnapshot();
      if(/Камера не построена:/.test(state.status))break;
      await delay(2000);
    }
    result.timings.backgroundWaitSeconds=(Date.now()-bgAt)/1000;
    project=await saveProject(page,dir);
    if(!Array.isArray(project.chunks)||!Array.isArray(project.clips)||!project.chunks.length)throw Error('Downloaded project has no actual transcript');
    if(Math.abs(project.duration-source.duration_sec)>2)throw Error('Project duration does not match the full source');
    result.transcript={rows:project.chunks.length,lastSpeechEnd:Math.max(...project.chunks.map(row=>Number(row.end)||0)),
      words:project.chunks.reduce((n,row)=>n+(Array.isArray(row.words)?row.words.length:0),0)};
    result.asr.reachedLastWindow=finishedAsr||cachedAsr||asrSeconds>=source.duration_sec-31;
    result.transcript.nearSourceEnd=result.transcript.lastSpeechEnd>=source.duration_sec*.9;
    if(!result.asr.reachedLastWindow)result.warnings.push('No observation proves the ASR loop reached the final source window');
    if(!result.transcript.nearSourceEnd)result.warnings.push('Transcript ends before the final 10% of the source; inspect trailing silence or missing speech');
    result.camera={present:!!project.lectureCamera,version:project.lectureCamera?.version,keys:project.lectureCamera?.keys?.length||0};
    if(!project.lectureCamera)result.warnings.push('The exported project does not contain a finished lecture camera track');
    result.clips=clipRows(project);
    await json(join(dir,'microtopics.json'),result.clips);
    await page.locator('.top-navigation [data-editor-tab="captions"]').click();
    try{await uiDownload(page,'#save-srt',join(dir,'transcript.srt'),30000);result.srtDownloaded=true}
    catch(error){result.srtDownloaded=false;result.errors.push({stage:'srt',message:safe(error.message)})}
    await page.locator('.top-navigation [data-editor-tab="clip"]').click();
    await cleanScreenshot(page,join(dir,'02-microtopics.png'));
    await persist();

    const exportAt=Date.now();
    for(const clip of result.clips) {
      if(clip.candidate||(clip.editorialStatus==='needs-more-context'&&clip.status!=='approved')){
        clip.exportReason='App requires human review/acceptance before export';continue;
      }
      if(remaining(deadline)<config.minimum_remaining_export_seconds*1000){
        clip.exportReason='Remaining source budget is insufficient to start another full clip';continue;
      }
      const clipAt=Date.now(),stem='clip-'+String(clip.index+1).padStart(3,'0'),mp4Path=join(dir,stem+'.mp4');
      try {
        await closeDetail(page);
        await page.locator('.top-navigation [data-editor-tab="clip"]').click();
        await page.locator('.microtopic-card[data-topic-index="'+clip.index+'"] .microtopic-card-title').click();
        if(!await page.locator('#export').isEnabled())throw Error('App disabled this clip export');
        if(await page.locator('#output-quality').inputValue()!=='standard')throw Error('The site did not retain standard export quality');
        await cleanScreenshot(page,join(dir,stem+'-editor.png'));
        let download=null;
        const onDownload=value=>{download=value};
        page.on('download',onDownload);
        try{
          await page.locator('#atlas-export-clip').click();
          while(!download&&remaining(deadline)>0){
            const state=await recordSnapshot();
            if(!state.cancelEnabled&&/^Ошибка:/.test(state.status))throw Error(safe(state.status));
            if(!state.cancelEnabled&&Date.now()-clipAt>10000&&!/Экспорт завершён/.test(state.status))
              throw Error('Export stopped without a downloadable MP4: '+safe(state.status));
            await delay(1000);
          }
          if(!download)throw Error('Source budget ended before this complete clip rendered');
        }finally{page.off('download',onDownload)}
        const failure=await download.failure();if(failure)throw Error('MP4 download failed: '+safe(failure));
        await download.saveAs(mp4Path);
        const probe=JSON.parse((await command('ffprobe',['-v','error','-show_format','-show_streams','-of','json',mp4Path],Math.min(30000,remaining(deadline)))).stdout);
        await json(join(dir,stem+'-ffprobe.json'),probe);
        const video=probe.streams.find(stream=>stream.codec_type==='video'),audio=probe.streams.find(stream=>stream.codec_type==='audio');
        const duration=Number(probe.format.duration);
        if(!video||!audio)throw Error('Export must contain both real video and original audio tracks');
        if(video.width!==720||video.height!==1280)throw Error('Unexpected standard export dimensions');
        if(Math.abs(duration-clip.outputSeconds)>Math.max(.75,clip.outputSeconds*.002))throw Error('Export duration does not match the complete topic EDL');
        clip.exportStatus='downloaded';clip.exportReason=null;clip.file=stem+'.mp4';
        clip.bytes=(await stat(mp4Path)).size;clip.actualSeconds=duration;clip.videoCodec=video.codec_name;clip.audioCodec=audio.codec_name;
        clip.exportSeconds=(Date.now()-clipAt)/1000;
        for(const [i,fraction] of [.1,.5,.9].entries()) {
          if(remaining(deadline)<10000)break;
          await command('ffmpeg',['-hide_banner','-loglevel','error','-y','-ss',String(Math.max(0,duration*fraction)),'-i',mp4Path,'-frames:v','1',join(dir,stem+'-frame-'+(i+1)+'.png')],Math.min(30000,remaining(deadline)))
            .catch(error=>result.warnings.push('Frame inspection for '+stem+': '+safe(error.message)));
        }
        console.log('CLIP_DOWNLOADED '+JSON.stringify({case:item.id,index:clip.index+1,seconds:duration,bytes:clip.bytes,elapsedSeconds:clip.exportSeconds}));
      } catch(error) {
        clip.exportStatus='failed';clip.exportReason=safe(error.message);clip.exportSeconds=(Date.now()-clipAt)/1000;
        if(await page.locator('#cancel').isEnabled().catch(()=>false))await page.locator('#cancel').click({timeout:5000}).catch(()=>{});
        result.errors.push({stage:'export',clip:clip.index,message:clip.exportReason});
      }
      await persist();
    }
    result.timings.exportsSeconds=(Date.now()-exportAt)/1000;
    await json(join(dir,'microtopics.json'),result.clips);
    result.exportCounts={proposed:result.clips.length,downloaded:result.clips.filter(c=>c.exportStatus==='downloaded').length,
      failed:result.clips.filter(c=>c.exportStatus==='failed').length,notRun:result.clips.filter(c=>c.exportStatus==='not_run').length};
    result.status=result.clips.length>0&&result.exportCounts.downloaded===result.clips.length&&result.asr.reachedLastWindow&&
      result.transcript.nearSourceEnd&&result.srtDownloaded&&result.errors.length===0?'complete':'incomplete';
    await saveProject(page,dir,'project-final.json').catch(error=>result.warnings.push('Final project download: '+safe(error.message)));
  } catch(error) {
    result.status=remaining(deadline)>0?'failed':'timeout';
    result.errors.push({stage:'case',message:safe(error.message)});
    if(page&&!page.isClosed()){
      if(await page.locator('#cancel').isEnabled().catch(()=>false))await page.locator('#cancel').click({timeout:5000}).catch(()=>{});
      await delay(1500);
      await saveProject(page,dir,'project-partial.json').catch(()=>{});
      await cleanScreenshot(page,join(dir,'failure.png')).catch(()=>{});
    }
  } finally {
    stopPolling=true;await polling?.catch(()=>{});
    result.finishedAt=now();result.timings.totalSeconds=(Date.now()-started)/1000;
    result.browserEvents=events;
    result.buildAfter=await buildMetadata();
    await json(join(dir,'browser-events.json'),events);
    await persist();
    await page?.close().catch(()=>{});
    await rm(mediaPath,{force:true});
    console.log('CASE_END '+JSON.stringify({id:item.id,status:result.status,totalSeconds:result.timings.totalSeconds,exports:result.exportCounts||null}));
  }
}

try {
  if(!process.env.AUDIT_CREDENTIALS_FILE)throw Error('An encrypted, authorized login handoff is required');
  let credentials=JSON.parse(await readFile(process.env.AUDIT_CREDENTIALS_FILE,'utf8'));
  await rm(process.env.AUDIT_CREDENTIALS_FILE,{force:true});
  context=await chromium.launchPersistentContext(join(root,'browser-profile'),{
    channel:'chrome',headless:true,acceptDownloads:true,viewport:{width:1440,height:1000},
    args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-timer-throttling','--disable-renderer-backgrounding']
  });
  if(config.disable_native_save_pickers)await context.addInitScript(()=>{
    Object.defineProperty(window,'showSaveFilePicker',{value:undefined,configurable:true});
    Object.defineProperty(window,'showDirectoryPicker',{value:undefined,configurable:true});
  });
  run.browserVersion=context.browser()?.version()||'persistent Chrome';
  const login=await context.newPage();
  run.viewport=login.viewportSize();
  run.browserUserAgent=await login.evaluate(()=>navigator.userAgent);
  if(run.browserVersion==='persistent Chrome')run.browserVersion=run.browserUserAgent.match(/Chrome\/([0-9.]+)/)?.[1]||null;
  await login.goto(config.production_url,{waitUntil:'domcontentloaded',timeout:60000});
  await login.locator('#auth-email').fill(credentials.email);
  await login.locator('#auth-password').fill(credentials.password);
  await login.locator('#auth-submit').click();
  credentials=null;
  await login.locator('#atlas-new-lecture').waitFor({timeout:45000});
  run.authenticatedAt=now();
  // Login page screenshots, response bodies, storage state, profiles, traces and HAR are never artifacts.
  await login.close();
  for(const item of cases){await runCase(item);await json(join(output,'run.json'),run)}
}catch(error){fatal=safe(error.message);run.fatalError=fatal}
finally{
  await context?.close().catch(()=>{});
  run.finishedAt=now();run.buildAfter=await buildMetadata();
  run.buildChanged=!!commitOf(run.buildBefore)&&!!commitOf(run.buildAfter)&&commitOf(run.buildBefore)!==commitOf(run.buildAfter);
  run.unexpectedBuild=!!config.expected_commit&&commitOf(run.buildBefore)!==config.expected_commit;
  run.summary={selected:cases.length,attempted:run.cases.length,complete:run.cases.filter(c=>c.status==='complete').length,
    downloadedClips:run.cases.reduce((sum,c)=>sum+c.clips.filter(clip=>clip.exportStatus==='downloaded').length,0)};
  await json(join(output,'run.json'),run);
  console.log('AUDIT_SUMMARY '+JSON.stringify({...run.summary,buildChanged:run.buildChanged,unexpectedBuild:run.unexpectedBuild,fatal:!!fatal}));
}
if(fatal||run.buildChanged||run.unexpectedBuild||run.summary.complete!==cases.length)process.exitCode=1;
