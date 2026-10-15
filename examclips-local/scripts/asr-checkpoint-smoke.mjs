import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const browserPath=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!browserPath)throw Error('Chrome unavailable');
const browser=await chromium.launch({executablePath:browserPath,headless:true,args:['--no-sandbox']});
const page=await browser.newPage();
try{
 await page.goto('http://127.0.0.1:5173/');
 const result=await page.evaluate(async()=>{
  const {checkpointKey,saveCheckpoint,loadCheckpoint,deleteCheckpoint,remainingWindows}=await import('/src/asr-checkpoint.js');
  const file=new File(['this lecture has private bytes'], 'lecture.mp4',{lastModified:1234});
  const other=new File(['a different video same filename'], 'lecture.mp4',{lastModified:1234});
  const key=await checkpointKey(file,'ru'),otherKey=await checkpointKey(other,'ru');
  await saveCheckpoint(key,{chunks:[{start:0,end:30,text:'Docker introduction'}],completedWindows:[0,30]});
  const before=await loadCheckpoint(key,90);
  const next=remainingWindows(90,90,before.completedWindows);
  await deleteCheckpoint(key);
  const after=await loadCheckpoint(key,90);
  return {differentFiles:key!==otherKey,rows:before.chunks.length,
    completed:before.completedWindows,next,erased:after.chunks.length===0&&after.completedWindows.length===0};
 });
 assert.equal(result.differentFiles,true);
 assert.equal(result.rows,1);
 assert.deepEqual(result.completed,[0,30]);
 assert.deepEqual(result.next,[60]);
 assert.equal(result.erased,true);
 console.log('ASR_RESUME_BROWSER_SUCCESS',JSON.stringify(result));
}finally{await browser.close()}
