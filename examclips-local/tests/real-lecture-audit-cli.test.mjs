import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const sample=[
 [289,320,'Containers are isolated processes that share the operating system kernel, unlike virtual machines which use guest systems.'],
 [323,347,'For example virtual machines run individual operating systems, while containers share the same host resources.'],
 [813,848,'A Dockerfile defines a base image using FROM, after which WORKDIR selects the working directory.'],
 [850,890,'The RUN command installs dependencies and COPY transfers application files to the Docker image.'],
 [940,987,'Docker build cache reuses unchanged layers and therefore makes repeated builds faster.'],
 [990,1038,'If dependencies remain unchanged, caching the application build avoids repeating expensive installation steps.'],
 [1110,1150,'By ordering the COPY step after the installation RUN step, we can retain the cache.'],
 [1154,1200,'Docker build reuses the prior layers when package files remain identical.']
];
test('real-ASR audit CLI compares baseline/refined, preserves source evidence and reports all 26 visual clues',()=>{
 const d=mkdtempSync(join(tmpdir(),'examclips-audit-'));
 try{
  const input=join(d,'asr.json'),out=join(d,'audit');
  writeFileSync(input,JSON.stringify({model:{model:'synthetic-test-only'},rows:sample.map(([start,end,text])=>({start,end,text}))}));
  const result=spawnSync(process.execPath,['scripts/audit-real-lecture.mjs',input,out],{
    cwd:process.cwd(),encoding:'utf8',timeout:25000
  });
  assert.equal(result.status,0,result.stderr||result.stdout);
  assert.equal(existsSync(join(out,'audit.md')),true);
  const report=JSON.parse(readFileSync(join(out,'audit.json'),'utf8'));
  assert.equal(report.source,'private original lecture ASR');
  assert.equal(report.originalVisualGuide.length,26);
  assert.equal(report.transcriptChunks,sample.length);
  assert.ok(report.videoCount>=1);
  assert.ok(report.baselineWithoutVisualGuides.videoCount>=1);
  assert.ok(report.chapters.some(x=>x.visualCandidates===5));
  assert.ok(report.videos.every(v=>Array.isArray(v.segments)));
 }finally{rmSync(d,{recursive:true,force:true})}
});
