// A preparation-only transport/UI gate. It does not count as a lecture quality result.
import {chromium} from 'playwright';
import {mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import {startServer} from './stand-server.mjs';
import {installNetworkPolicy,TARGET,ORIGIN} from './stand-policy.mjs';

const HERE=dirname(fileURLToPath(import.meta.url));
const config=JSON.parse(await readFile(join(HERE,'stand-config.json'),'utf8'));
if(!process.env.AUDIT_ROOT||!process.env.AUDIT_OUT)throw Error('Runner-private audit and evidence paths required');
const root=resolve(process.env.AUDIT_ROOT),fixture=join(root,'ui-smoke-source.mp4'),evidence=join(resolve(process.env.AUDIT_OUT),'bundle-prepare');
await mkdir(evidence,{recursive:true,mode:0o700});
const diagnostic=value=>String(value||'').replace(/https?:\/\/[^\s"'<>]+/g,value=>{try{const url=new URL(value);return url.origin+url.pathname}catch{return '[url]'}})
 .replace(/Bearer\s+[A-Za-z0-9._-]+/gi,'Bearer [redacted]').replace(/eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,'[token]').slice(0,3000);
let stage='generate_fixture',server,browser,page;const denied=[],models=new Set(),report={targetKind:'test_instance',scope:'preparation_ui_fixture_only',sourceCommit:config.source_commit,artifactId:config.artifact_id,artifactSha256:config.artifact_sha256};
try{
 await mkdir(root,{recursive:true,mode:0o700});
 await new Promise((yes,no)=>{
  const child=spawn('ffmpeg',['-hide_banner','-loglevel','error','-nostdin','-y','-f','lavfi','-i','testsrc2=size=640x360:rate=15:duration=4',
   '-f','lavfi','-i','sine=frequency=440:sample_rate=48000:duration=4','-c:v','libx264','-pix_fmt','yuv420p','-c:a','aac','-shortest',fixture],{stdio:'ignore',timeout:45000});
  child.on('error',()=>no(Error('Fixture tool failed')));child.on('close',code=>code===0?yes():no(Error('Fixture generation failed')));
 });
 stage='start_verified_server';server=await startServer(join(root,'site'),config);
 stage='launch_official_chrome';browser=await chromium.launch({channel:'chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const context=await browser.newContext({serviceWorkers:'block',viewport:{width:1440,height:1000}});
 await installNetworkPolicy(context,{denied,models});page=await context.newPage();page.setDefaultTimeout(20000);
 stage='open_app';await page.goto(TARGET,{waitUntil:'domcontentloaded',timeout:45000});await page.locator('#atlas-new-lecture').waitFor();
 report.crossOriginIsolated=await page.evaluate(()=>crossOriginIsolated);assert.equal(report.crossOriginIsolated,true);
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
 assert.ok(report.source.duration>3.8&&report.source.duration<4.2);assert.equal(report.source.error,null);
 stage='verify_no_backend';report.capabilities={};
 for(const path of ['/api/local-ocr-capabilities','/api/local-review-capabilities']){
  const response=await fetch(ORIGIN+path,{redirect:'error',signal:AbortSignal.timeout(3000)});assert.equal(response.status,404);report.capabilities[path]=response.status;
 }
 assert.equal(denied.length,0);report.deniedRequests=denied;report.publicModelAssets=[...models];report.status='passed';
 await writeFile(join(evidence,'ui-smoke-report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
 console.log('STAND_UI_SMOKE_SUCCESS '+JSON.stringify(report));
}catch(error){
 report.status='failed';report.stage=stage;report.errorType=error.name;report.errorMessage=diagnostic(error.message);report.deniedRequests=denied;
 if(page&&!page.isClosed()){
  try{await page.screenshot({path:join(evidence,'ui-smoke-failure.png'),fullPage:false,timeout:5000,mask:[page.locator('#auth-gate'),page.locator('.billing-dialog')]});report.failureScreenshot='ui-smoke-failure.png'}catch{report.failureScreenshot=null}
 }
 await writeFile(join(evidence,'ui-smoke-report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600}).catch(()=>{});
 console.error('STAND_UI_SMOKE_FAILED '+JSON.stringify({stage,errorType:error.name,errorMessage:report.errorMessage,deniedRequests:denied}));process.exitCode=1;
}finally{await browser?.close();if(server)await new Promise(done=>server.close(done));await rm(fixture,{force:true})}
