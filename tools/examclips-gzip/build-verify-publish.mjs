import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {gzipSync as nodeGzip,gunzipSync as nodeGunzip} from 'node:zlib';
import vm from 'node:vm';
import * as esbuild from 'esbuild';

const REPO='MakSoS1/analytics_test',BRANCH='qa/examclips-audit-2026-11-11';
if(process.env.GITHUB_REPOSITORY!==REPO||process.env.GITHUB_REF_NAME!==BRANCH)throw Error('PUBLIC_HELPER_IDENTITY_MISMATCH');
const VERSION='0.8.2',INTEGRITY='sha512-cPJU47OaAoCbg0pBvzsgpTPhmhqI5eJjh/JIu8tPj5q+T7iLvW/JAYUqmE7KOB4R1ZyEhzBaIQpQpardBF5z8A==';
const hash=(data,algorithm='sha256')=>createHash(algorithm).update(data).digest('hex');
const gitBlob=data=>hash(Buffer.concat([Buffer.from('blob '+data.length+'\0'),data]),'sha1');
const lock=JSON.parse(await readFile('package-lock.json','utf8'));
assert.equal(lock.packages['node_modules/fflate'].version,VERSION);
assert.equal(lock.packages['node_modules/fflate'].integrity,INTEGRITY);
assert.equal(esbuild.version,'0.28.2');
async function publicFetch(url,max){
 const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(30000)});
 if(!response.ok)throw Error('PUBLIC_PACKAGE_HTTP_'+response.status);
 const bytes=Buffer.from(await response.arrayBuffer());
 if(bytes.length>max)throw Error('PUBLIC_PACKAGE_TOO_LARGE');
 return bytes;
}
const manifest=JSON.parse((await publicFetch('https://registry.npmjs.org/fflate/'+VERSION,100000)).toString('utf8'));
assert.equal(manifest.dist.integrity,INTEGRITY);
assert.equal(manifest.dist.tarball,'https://registry.npmjs.org/fflate/-/fflate-0.8.2.tgz');
const tarball=await publicFetch(manifest.dist.tarball,1000000);
assert.equal('sha512-'+createHash('sha512').update(tarball).digest('base64'),INTEGRITY);
const tar=nodeGunzip(tarball,{maxOutputLength:8*1024**2}),members=new Map();
for(let offset=0;offset+512<=tar.length;){
 const header=tar.subarray(offset,offset+512);
 if(header.every(x=>x===0))break;
 const name=header.subarray(0,100).toString('utf8').replace(/\0.*$/s,'');
 const size=parseInt(header.subarray(124,136).toString('ascii').replace(/\0.*$/s,'').trim(),8)||0;
 assert.ok(Number.isSafeInteger(size)&&size>=0&&offset+512+size<=tar.length);
 if(['package/esm/browser.js','package/LICENSE'].includes(name))members.set(name,tar.subarray(offset+512,offset+512+size));
 offset+=512+Math.ceil(size/512)*512;
}
const source=await readFile('node_modules/fflate/esm/browser.js');
assert.ok(members.has('package/esm/browser.js'));
assert.deepEqual(source,members.get('package/esm/browser.js'),'installed browser source must exactly match pinned tarball');
assert.ok(members.has('package/LICENSE'),'MIT license must be retained');
const built=await esbuild.build({entryPoints:['entry.mjs'],bundle:true,platform:'browser',format:'iife',globalName:'ExamClipsGzip',target:'es2020',minify:true,legalComments:'inline',write:false});
const bundle=built.outputFiles[0].text;
assert.ok(Buffer.byteLength(bundle)<100000,'synchronous compression bundle is bounded');
assert.equal(/\b(?:Worker|fetch|XMLHttpRequest|WebSocket|importScripts|CompressionStream|DecompressionStream)\b/.test(bundle),false,'bundle must have no worker/network/compression-platform dependency');
const sandbox=vm.createContext({Buffer:undefined,process:undefined,require:undefined,Worker:undefined,fetch:undefined,
 TextEncoder:undefined,TextDecoder:undefined,CompressionStream:undefined,DecompressionStream:undefined,
 URL:undefined,Blob:undefined,window:undefined,document:undefined,self:undefined});
vm.runInContext(bundle,sandbox,{timeout:10000});
const client=sandbox.ExamClipsGzip;
assert.deepEqual(Object.keys(client).sort(),['gunzipSync','gzipSync']);
const binary=Buffer.alloc(1024*1024);
let state=0x12345678;for(let i=0;i<binary.length;i++){state=(Math.imul(state,1664525)+1013904223)>>>0;binary[i]=state>>>24;}
const syntheticProject=JSON.stringify({schema:2,duration:7500,chunks:Array.from({length:20000},(_,i)=>({
 id:i,start:i/3,end:i/3+.25,text:'Публичная проверка — synthetic lecture JSON, Ελληνικά, 🧪, x squared plus y squared and widget actions.'
})),clips:[{id:'public-fixture',title:'Synthetic compression data'}]});
const repeated=Buffer.from(JSON.stringify({fixture:'public-only-no-project-or-credentials',projectBase64:Buffer.from(syntheticProject).toString('base64')}));
assert.ok(repeated.length>2*1024**2);
const fixtures=[
 ['empty',Buffer.alloc(0)],['unicode',Buffer.from('Русский Ελληνικά 🧪 漢字 é\n'.repeat(1000))],
 ['binary',binary],['repetitive_multi_mb_json',repeated]
];
const results=[];
for(const [name,plain] of fixtures){
 const started=performance.now(),packed=Buffer.from(client.gzipSync(new Uint8Array(plain)));
 assert.deepEqual(packed,Buffer.from(client.gzipSync(new Uint8Array(plain))),'deterministic repeated gzip');
 assert.deepEqual([...packed.subarray(4,8)],[0,0,0,0],'mtime must be zero');
 assert.deepEqual(nodeGunzip(packed,{maxOutputLength:16*1024**2}),plain,'Node must decode V8 bundle gzip');
 assert.deepEqual(Buffer.from(client.gunzipSync(new Uint8Array(nodeGzip(plain,{mtime:0})))),plain,'V8 bundle must decode Node gzip');
 assert.deepEqual(Buffer.from(client.gunzipSync(new Uint8Array(packed))),plain,'bundle round-trip');
 if(name==='repetitive_multi_mb_json')assert.ok(packed.length<=600000,'representative multi-MB JSON must fit native compressed-input cap');
 results.push({name,plainBytes:plain.length,compressedBytes:packed.length,plainSha256:hash(plain),compressedSha256:hash(packed),
  elapsedMs:Math.round(performance.now()-started),nodeDecodesBundle:true,bundleDecodesNode:true,deterministicMtimeZero:true});
}
const bundleBytes=Buffer.from(bundle),license=members.get('package/LICENSE');
const report={
 version:1,purpose:'public_gzip_interoperability_helper',privateInputsUsed:false,corpusCountIncrement:0,
 repository:REPO,branch:BRANCH,runId:process.env.GITHUB_RUN_ID,runAttempt:process.env.GITHUB_RUN_ATTEMPT,sourceCommit:process.env.GITHUB_SHA,
 createdAt:new Date().toISOString(),package:{name:'fflate',version:VERSION,integrity:INTEGRITY,tarballSha256:hash(tarball),
  sourceRepository:'https://github.com/101arrowz/fflate',sourceTag:'v0.8.2',sourceCommit:'d3243651cb142e3e04f3e4bc037b9e985878f444',
  upstreamSourceGitBlobSha:'4ebb37293b8a593f0a45f62092d4959c06956259',installedBrowserSourceSha256:hash(source)},
 bundler:{name:'esbuild',version:esbuild.version},exports:['gzipSync','gunzipSync'],gzipOptions:{level:6,mtime:0},
 bundleBytes:bundleBytes.length,bundleSha256:hash(bundleBytes),bundleGitBlobSha:gitBlob(bundleBytes),
 sandboxMissingGlobals:['Buffer','process','require','Worker','fetch','TextEncoder','TextDecoder','CompressionStream','DecompressionStream','URL','Blob','window','document','self'],
 fixtures:results,status:'passed'
};
await writeFile('gzip-bundle.js',bundle);
await writeFile('verification.json',JSON.stringify(report,null,2)+'\n');
const token=process.env.GITHUB_TOKEN;if(!token)throw Error('GITHUB_TOKEN_MISSING');
async function gh(path,method='GET',body){
 const response=await fetch('https://api.github.com/repos/'+REPO+path,{method,
  headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28'},
  body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
 if(!response.ok){const error=Error('PUBLICATION_HTTP_'+response.status);error.status=response.status;throw error;}
 return response.json();
}
const prefix='.audit-gzip/'+process.env.GITHUB_RUN_ID+'/'+process.env.GITHUB_RUN_ATTEMPT;
const verifiedBlob=await gh('/git/blobs','POST',{content:bundle,encoding:'utf-8'});
assert.equal(verifiedBlob.sha,report.bundleGitBlobSha,'GitHub blob identity must match local calculation');
const entries=[
 {path:prefix+'/gzip-bundle.js',mode:'100644',type:'blob',sha:verifiedBlob.sha},
 {path:prefix+'/verification.json',mode:'100644',type:'blob',content:JSON.stringify(report,null,2)+'\n'},
 {path:prefix+'/fflate-LICENSE.txt',mode:'100644',type:'blob',content:license.toString('utf8')}
];
let published=null;
for(let attempt=0;attempt<12;attempt++){
 const ref=await gh('/git/ref/heads/'+BRANCH),parent=await gh('/git/commits/'+ref.object.sha);
 const tree=await gh('/git/trees','POST',{base_tree:parent.tree.sha,tree:entries});
 const commit=await gh('/git/commits','POST',{message:'Publish tested public gzip interoperability bundle '+process.env.GITHUB_RUN_ID,parents:[parent.sha],tree:tree.sha});
 try{await gh('/git/refs/heads/'+BRANCH,'PATCH',{sha:commit.sha,force:false});published=commit.sha;break;}
 catch(error){if(![409,422].includes(error.status)||attempt===11)throw error;await new Promise(r=>setTimeout(r,1000));}
}
assert.ok(published);
console.log('PUBLIC_GZIP_HELPER_READY '+JSON.stringify({prefix,commit:published,bundleSha256:report.bundleSha256,bundleGitBlobSha:report.bundleGitBlobSha,bundleBytes:report.bundleBytes,fixtures:results}));
