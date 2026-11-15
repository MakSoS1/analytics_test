import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import http from 'node:http';

const get=(port,path,headers={})=>new Promise((yes,no)=>{
 const request=http.get({hostname:'127.0.0.1',port,path,headers},response=>{
  let body='';response.setEncoding('utf8');response.on('data',data=>body+=data);response.on('end',()=>yes({status:response.statusCode,headers:response.headers,body}));
 });request.on('error',no);
});
async function fixture(){
 const directory=await mkdtemp(join(tmpdir(),'stand-server-test-'));await mkdir(join(directory,'app'));
 const body='<!doctype html><title>Local test fixture</title>';await writeFile(join(directory,'app/index.html'),body);
 return {directory,config:{target_kind:'test_instance',target_url:'http://127.0.0.1:5173/app/',source_commit:'a'.repeat(40),source_tag:'v-test',artifact_id:1,artifact_sha256:'b'.repeat(64),ci_run_id:2,
  assets:[{path:'app/index.html',bytes:Buffer.byteLength(body),sha256:createHash('sha256').update(body).digest('hex')}]}};
}
test('static instance serves only verified declared assets and truthfully identifies its build',async()=>{
 const {startServer}=await import('./stand-server.mjs');const {directory,config}=await fixture();let server;
 try{
  server=await startServer(directory,config,{port:0});const port=server.address().port;
  const index=await get(port,'/app/');assert.equal(index.status,200);assert.match(index.body,/Local test fixture/);
  assert.equal(index.headers['cross-origin-opener-policy'],'same-origin');assert.equal(index.headers['cross-origin-embedder-policy'],undefined);
  assert.match(index.headers['content-security-policy'],/connect-src 'self'/);assert.doesNotMatch(index.headers['content-security-policy'],/examclips\.dpdns/);
  const build=JSON.parse((await get(port,'/site-build.json')).body);assert.equal(build.targetKind,'test_instance');assert.equal(build.commit,config.source_commit);assert.equal(build.artifactSha256,config.artifact_sha256);
  for(const path of ['/auth/v1/token','/billing-api/account','/api/local-review-capabilities','/app/secret.pem','/app/%2e%2e/secret','/../secret'])assert.notEqual((await get(port,path)).status,200);
  assert.equal((await get(port,'/app/',{Host:'examclips.dpdns.org'})).status,421);
 }finally{if(server)await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true})}
});
test('static instance refuses an asset whose content differs from pinned metadata',async()=>{
 const {startServer}=await import('./stand-server.mjs');const {directory,config}=await fixture();
 try{await writeFile(join(directory,'app/index.html'),'changed');await assert.rejects(startServer(directory,config,{port:0}),/integrity/)}
 finally{await rm(directory,{recursive:true,force:true})}
});
