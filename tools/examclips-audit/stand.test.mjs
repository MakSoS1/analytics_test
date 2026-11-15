import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const pair=generateKeyPairSync('rsa',{modulusLength:4096,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
const identity={repository:'MakSoS1/analytics_test',branch:'qa/examclips-stand45-retry-observed-2026-11-15',runId:'123456',runAttempt:'1',caseId:'ru03'};
async function policy(){const x=await import('./stand-policy.mjs').catch(()=>null);assert.ok(x,'Stand isolation policy must exist');return x;}
async function bundle(){const x=await import('./stand-bundle.mjs').catch(()=>null);assert.ok(x,'Stand bundle transport must exist');return x;}

test('stand target is exactly loopback and cannot be a production or demo target',async()=>{
 const p=await policy();assert.equal(p.assertLocalTarget('http://127.0.0.1:5173/app/'),'http://127.0.0.1:5173/app/');
 for(const value of ['https://examclips.dpdns.org/app/','http://localhost:5173/app/','http://127.0.0.1:5173/app/?demo','http://127.0.0.1:5173/app/#signup','http://user@127.0.0.1:5173/app/'])assert.throws(()=>p.assertLocalTarget(value));
});

test('production auth billing and lookalike destinations are blocked before request dispatch',async()=>{
 const p=await policy();
 for(const url of ['https://examclips.dpdns.org/billing-api/trial','https://examclips.dpdns.org/auth/v1/token','https://examclips.dpdns.org/app/','https://evil.example/','https://huggingface.co.evil.example/model','http://127.0.0.1:5173/billing-api/trial','http://127.0.0.1:5173/auth/v1/token'])assert.equal(p.requestPolicy(url).allowed,false,url);
 for(const url of ['http://127.0.0.1:5173/app/','http://127.0.0.1:5173/app/assets/worker.js','https://huggingface.co/model','https://cas-bridge.xethub.hf.co/model','https://cdn.jsdelivr.net/npm/tesseract.js','https://tessdata.projectnaptha.com/4.0.0/eng.traineddata.gz'])assert.equal(p.requestPolicy(url).allowed,true,url);
});

test('external model origins allow downloads and preflight only',async()=>{
 const p=await policy(),url='https://huggingface.co/model/weights.onnx';
 for(const method of ['GET','HEAD','OPTIONS'])assert.equal(p.requestPolicy(url,method).allowed,true);
 for(const method of ['POST','PUT','PATCH','DELETE'])assert.equal(p.requestPolicy(url,method).allowed,false);
});

test('handoff payloads are role-specific and never accept account credentials',async()=>{
 const p=await policy();
 assert.deepEqual(p.validatePayload('stand-bundle-prepare',{artifactUrl:'https://sdmntpreastus2.oaiusercontent.com/artifact?sig=fixture',bundleRecipientPublicKeyPem:pair.publicKey}),{artifactUrl:'https://sdmntpreastus2.oaiusercontent.com/artifact?sig=fixture',bundleRecipientPublicKeyPem:pair.publicKey});
 assert.equal(p.validatePayload('stand-bundle-unlock',{bundlePrivateKeyPem:pair.privateKey}).bundlePrivateKeyPem,pair.privateKey);
 assert.throws(()=>p.validatePayload('stand-bundle-unlock',{email:'test@example.invalid',password:'fixture'}));
 assert.throws(()=>p.validatePayload('stand-bundle-prepare',{artifactUrl:'https://examclips.dpdns.org/app/',bundleRecipientPublicKeyPem:pair.publicKey}));
 assert.throws(()=>p.validatePayload('stand-bundle-prepare',{artifactUrl:'https://sdmntpreastus2.oaiusercontent.com/artifact',bundleRecipientPublicKeyPem:pair.publicKey,extra:'forbidden'}));
});

test('a private bundle download redirect may not contact production or arbitrary origins',async()=>{
 const p=await policy();let calls=0;
 await assert.rejects(p.fetchArtifact('https://sdmntpreastus2.oaiusercontent.com/artifact',async()=>{
  calls++;return new Response('',{status:302,headers:{location:'https://examclips.dpdns.org/billing-api/account'}});
 }),/origin/i);assert.equal(calls,1);
});

test('shared bundle envelope is bound to repository branch run and attempt',async()=>{
 const b=await bundle();const context=b.bundleContext(identity);
 assert.equal(context.purpose,'stand-bundle');assert.equal(context.caseId,'bundle-prepare');
 const {seal,open}=await import('./crypto.mjs');
 const envelope=seal(Buffer.from('synthetic CI bytes'),pair.publicKey,context);
 assert.equal(open(envelope,pair.privateKey,context).toString(),'synthetic CI bytes');
 assert.throws(()=>open(envelope,pair.privateKey,b.bundleContext({...identity,runId:'123457'})));
 assert.throws(()=>open(envelope,pair.privateKey,b.bundleContext({...identity,runAttempt:'2'})));
 assert.throws(()=>b.bundleContext({...identity,branch:'main'}));
});

test('bundle transport verifies actual ciphertext and original archive hashes',async()=>{
 const b=await bundle();const root=await mkdtemp(join(tmpdir(),'stand-transport-'));
 try{
  const source=join(root,'source.zip'),dir=join(root,'encrypted'),restored=join(root,'restored.zip');
  const bytes=Buffer.from('PK synthetic fixture bytes');await writeFile(source,bytes);
  const {createHash}=await import('node:crypto');const expected={artifact_id:1,artifact_bytes:bytes.length,artifact_sha256:createHash('sha256').update(bytes).digest('hex'),source_commit:'a'.repeat(40),ci_run_id:1};
  await b.encryptBundle(source,dir,pair.publicKey,identity,expected);
  await b.decryptBundle(dir,restored,pair.privateKey,identity,expected);assert.deepEqual(await readFile(restored),bytes);
  const meta=JSON.parse(await readFile(join(dir,'bundle-encryption.json'),'utf8'));meta.ciphertextSha256='0'.repeat(64);await writeFile(join(dir,'bundle-encryption.json'),JSON.stringify(meta));
  await assert.rejects(b.decryptBundle(dir,join(root,'bad.zip'),pair.privateKey,identity,expected),/integrity/i);
 }finally{await rm(root,{recursive:true,force:true})}
});

test('denial records and error formatting remove signed URLs and secret payloads',async()=>{
 const p=await policy();const denied=p.requestPolicy('https://examclips.dpdns.org/billing-api/trial?token=PRIVATE_FIXTURE');
 assert.equal(JSON.stringify(denied).includes('PRIVATE_FIXTURE'),false);
 assert.equal(p.publicFailure(new Error('https://private.example/?key=PRIVATE_FIXTURE')).includes('PRIVATE_FIXTURE'),false);
});
