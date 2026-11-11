import {chromium} from 'playwright';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {identityFromEnv,safeError} from './native-context.mjs';
const execute=promisify(execFile),HERE=dirname(fileURLToPath(import.meta.url)),identity=identityFromEnv();
const work=join(resolve(process.env.AUDIT_ROOT),'picker-preflight'),output=join(resolve(process.env.AUDIT_OUT),identity.caseId);
const ui=join(output,'technical-ui','fixture');await mkdir(work,{recursive:true,mode:0o700});await mkdir(ui,{recursive:true,mode:0o700});
const fixture=join(work,'fixture.mp4'),target=join(work,'native-clip.mp4'),hash=b=>createHash('sha256').update(b).digest('hex');
let browser,server;let result={auditKind:'native_picker_transport_fixture',supplementary:true,corpusCountIncrement:0,startedAt:new Date().toISOString(),
  scope:'Synthetic 2.4-second MP4 bytes through the real native API and OS dialog; no ExamClips account, project, ASR or renderer',nativeApiReplaced:false,qualityVerdict:null};
try{
  await execute('ffmpeg',['-v','error','-f','lavfi','-i','testsrc2=size=160x90:rate=15','-f','lavfi','-i','sine=frequency=440:sample_rate=48000',
    '-t','2.4','-c:v','libx264','-threads','2','-pix_fmt','yuv420p','-c:a','aac','-movflags','+faststart','-y',fixture],{timeout:30000});
  const media=await readFile(fixture);
  const html='<!doctype html><meta charset="utf-8"><title>Native picker preflight</title><h1>Native picker preflight</h1><p>Synthetic short media. No ExamClips account or project.</p><button id="save" disabled>Save fixture MP4</button><p id="status">Loading fixture</p><script>let bytes;fetch("/fixture.mp4").then(r=>r.arrayBuffer()).then(b=>{bytes=b;document.querySelector("#save").disabled=false;document.querySelector("#status").textContent="ready"});document.querySelector("#save").onclick=async()=>{try{const h=await showSaveFilePicker({suggestedName:"native-clip.mp4",types:[{description:"MP4 video",accept:{"video/mp4":[".mp4"]}}]});const w=await h.createWritable();await w.write(bytes);await w.close();document.querySelector("#status").textContent="native-written"}catch(e){document.querySelector("#status").textContent="failed:"+e.name}};</script>';
  server=createServer((request,response)=>{if(request.url==='/fixture.mp4'){response.writeHead(200,{'Content-Type':'video/mp4'});response.end(media)}else{response.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});response.end(html)}});
  await new Promise(resolvePromise=>server.listen(0,'127.0.0.1',resolvePromise));
  browser=await chromium.launchPersistentContext(join(work,'browser-profile'),{channel:'chrome',headless:false,viewport:{width:1440,height:1000},
    args:['--no-sandbox','--disable-dev-shm-usage','--lang=en-US','--window-size=1460,1120','--no-first-run']});
  const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  await page.waitForFunction(()=>document.querySelector('#status').textContent==='ready',{},{timeout:10000});
  result.browser=await page.evaluate(()=>({secureContext:isSecureContext,userAgent:navigator.userAgent,pickerSource:Function.prototype.toString.call(showSaveFilePicker)}));
  if(!result.browser.secureContext||!result.browser.pickerSource.includes('[native code]'))throw Error('PREFLIGHT_NATIVE_API_UNAVAILABLE');
  const before=join(work,'windows-before.json');await execute('python3',[join(HERE,'native-dialog.py'),'snapshot','--output',before],{timeout:30000});
  const picker=execute('python3',[join(HERE,'native-dialog.py'),'operate','--before',before,'--target',target,'--case-dir',work,'--evidence-dir',ui,'--timeout','45'],{timeout:70000,maxBuffer:8192});picker.catch(()=>{});
  await page.locator('#save').click();await picker;
  await page.waitForFunction(()=>document.querySelector('#status').textContent==='native-written',{},{timeout:10000});
  const saved=await readFile(target);if(hash(saved)!==hash(media))throw Error('PREFLIGHT_NATIVE_BYTES_DIFFER');
  await execute('python3',[join(HERE,'media_validation.py'),target,'--expected-seconds','2.4','--expected-frames','36','--report',join(work,'media-validation.json')],{timeout:30000});
  result={...result,status:'genuine_native_picker_preflight_passed',bytes:saved.length,sha256:hash(saved),sourceSha256:hash(media),
    dialog:JSON.parse(await readFile(join(ui,'native-dialog.json'),'utf8')),media:JSON.parse(await readFile(join(work,'media-validation.json'),'utf8'))};
}catch(error){result.status='native_picker_preflight_failed';result.failureCode=safeError(error);process.exitCode=1}
finally{
  if(browser){let timeout;await Promise.race([browser.close().catch(()=>{}),new Promise(resolvePromise=>{timeout=setTimeout(resolvePromise,15000)})]);clearTimeout(timeout)}
  if(server)await new Promise(resolvePromise=>server.close(resolvePromise));
  result.finishedAt=new Date().toISOString();await writeFile(join(output,'native-picker-preflight.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
  await rm(join(work,'browser-profile'),{recursive:true,force:true});
  console.log('NATIVE_PICKER_PREFLIGHT '+JSON.stringify({status:result.status,bytes:result.bytes,sha256:result.sha256,failureCode:result.failureCode,auditKind:result.auditKind,corpusCountIncrement:0}));
}
process.exit(process.exitCode||0);
