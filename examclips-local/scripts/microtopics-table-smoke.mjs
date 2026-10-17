import {chromium} from 'playwright-core';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const executablePath=['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!executablePath)throw Error('Chrome required');
const browser=await chromium.launch({headless:true,executablePath,args:['--no-sandbox','--disable-dev-shm-usage']});
const lines=[
 [0,8,'About me. I have 15 years of development and software engineering experience.'],
 [9,18,'Lecture 1 brief. What is container, Dockerfile, lifecycle and Docker networking.'],
 [28,44,'Docker containers isolate application processes and dependencies from other workloads.'],
 [45,60,'For example, a container shares the host operating system kernel, while a virtual machine runs a guest operating system.'],
 [65,82,'Next topic: Dockerfile and image build. A Dockerfile describes how to create a reproducible container image.'],
 [83,97,'For example, the Docker build command executes each step in the Dockerfile.'],
 [110,132,'Next topic: Docker networking. The bridge network connects containers to docker0.'],
 [133,157,'For example, an overlay network connects containers across multiple hosts.'],
 [158,173,'Therefore Docker networks allow multiple services to communicate securely.']
];
const t=n=>{const ms=Math.round(n*1000);const h=Math.floor(ms/3600000);const m=Math.floor((ms%3600000)/60000),s=Math.floor((ms%60000)/1000),r=ms%1000;return [h,m,s].map(v=>String(v).padStart(2,'0')).join(':')+','+String(r).padStart(3,'0')};
const srt=lines.map((r,i)=>[i+1,t(r[0])+' --> '+t(r[1]),r[2],''].join('\n')).join('\n');
try{
 const page=await browser.newPage({viewport:{width:1440,height:960}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:5173/');
 await page.locator('#video-file').setInputFiles('selective-lecture-fixture.mp4');
 await page.waitForFunction(()=>!document.querySelector('#import-srt').disabled);
 await page.locator('#srt-file').setInputFiles({name:'docker-topics.srt',mimeType:'text/plain',buffer:Buffer.from(srt)});
 await page.waitForFunction(()=>document.querySelector('#app')?.dataset.phase==='results');
 await page.locator('.top-navigation [data-editor-tab="clip"]').click();
 assert.equal(await page.locator('.top-navigation [data-editor-tab="clip"]').textContent(),'Микротемы');
 assert.ok(await page.locator('#microtopic-catalog').isVisible());
 const cards=page.locator('.microtopic-card');
 assert.ok(await cards.count()>=2,'Expected multiple microtopics: '+await cards.count());
 const names=await page.locator('.microtopic-card-title').allTextContents();
 assert.ok(names.some(x=>/Dockerfile/i.test(x)),'No Dockerfile topic: '+names);
 assert.ok(names.some(x=>/сет|network/i.test(x)),'No networking topic: '+names);
 assert.ok(!names.some(x=>/about me|lecture 1 brief/i.test(x)),'Intro became a microtopic');
 await page.locator('.microtopic-card-title').last().click();
 assert.ok(await page.locator('#microtopic-preview').isVisible());
 assert.ok(await page.locator('#microtopic-detail').isVisible());
 assert.ok(await page.locator('.microtopic-detail-script').isVisible());
 const fullText=await page.locator('.microtopic-detail-transcript').textContent();
 assert.ok(fullText.includes('00:01:50'),'Source timestamp missing: '+fullText);
 const proofs=page.locator('.microtopic-proof');
 assert.ok(await proofs.count()>0,'A concise screenplay must cite original speech');
 await page.locator('#catalog-preview-play').click();
 await page.locator('#microtopic-back').click();
 assert.ok(await page.locator('.microtopic-grid').isVisible());
 assert.equal(await cards.count(),names.length);
 await page.screenshot({path:'microtopics-gallery.png',fullPage:false});
 assert.deepEqual(errors,[]);
 console.log('MICROTOPIC_TABLE_SUCCESS',JSON.stringify({count:await cards.count(),names,proofs:await proofs.count(),transcriptEvidence:true}));
}finally{await browser.close()}
