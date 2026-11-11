import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {openFile} from './crypto.mjs';
let pack={};try{pack=await import('./package-evidence.mjs')}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error}
const execute=promisify(execFile),HERE=dirname(fileURLToPath(import.meta.url));
const identity={repository:'MakSoS1/analytics_test',branch:'qa/examclips-audit-2026-11-11',runId:'999123',runAttempt:'1',caseId:'rul01'};
const keys=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
async function fixture(){
  const root=await mkdtemp(join(tmpdir(),'native-package-test-')),output=join(root,'evidence'),artifact=join(root,'sealed'),privateRoot=join(root,'private');
  await mkdir(join(output,'rul01'),{recursive:true});await mkdir(privateRoot);
  const run={...identity,auditKind:'native_export_probe',supplementary:true,corpusCountIncrement:0};
  const bytes=Buffer.alloc(8192,73);
  const result={id:'rul01',auditKind:'native_export_probe',supplementary:true,corpusCountIncrement:0,status:'native_export_saved_and_decoded',clips:[{file:'native-clip.mp4',exportStatus:'saved_native',bytes:8192,sha256:createHash('sha256').update(bytes).digest('hex')}]};
  await writeFile(join(output,'run.json'),JSON.stringify(run));await writeFile(join(output,'rul01','result.json'),JSON.stringify(result));
  await writeFile(join(output,'rul01','native-clip.mp4'),bytes);await writeFile(join(output,'rul01','project-input.json'),JSON.stringify({clips:[],chunks:[{text:'The word password in a lecture is not an account secret.'}]}));
  const publicKeyFile=join(root,'recipient.pub.pem');await writeFile(publicKeyFile,keys.publicKey);
  return {root,output,artifact,privateRoot,publicKeyFile,identity,bytes};
}
test('native evidence encrypts, partitions and restores exact bytes with the verified evidence context',async()=>{
  assert.equal(typeof pack.packageEvidence,'function');const f=await fixture();
  try{
    const manifest=await pack.packageEvidence(f);assert.equal(manifest.parts.length,1);
    const cipher=join(f.root,'joined.enc');await execute('python3',[join(HERE,'split_evidence.py'),'join',f.artifact,cipher]);
    const meta=JSON.parse(await readFile(join(f.artifact,'part-0001','encryption.json'),'utf8'));
    assert.deepEqual(meta.context,{purpose:'evidence',...identity});
    const clear=join(f.root,'restored.zip');await openFile(cipher,clear,meta,keys.privateKey,{purpose:'evidence',...identity});
    const {stdout}=await execute('python3',['-c',"import hashlib,json,sys,zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z: print(json.dumps({n:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}))",clear]);
    const hashes=JSON.parse(stdout);assert.equal(hashes['rul01/native-clip.mp4'],createHash('sha256').update(f.bytes).digest('hex'));
    await assert.rejects(()=>stat(join(f.privateRoot,'evidence.zip')),{code:'ENOENT'});await assert.rejects(()=>stat(join(f.artifact,'evidence.enc')),{code:'ENOENT'});
  }finally{await rm(f.root,{recursive:true,force:true})}
});
test('account material is rejected even when hidden as a key inside a project JSON',async()=>{
  assert.equal(typeof pack.packageEvidence,'function');const f=await fixture();
  try{
    await writeFile(join(f.output,'rul01','project-input.json'),JSON.stringify({clips:[],nested:{password:'do-not-archive-this-fixture'}}));
    await assert.rejects(()=>pack.packageEvidence(f),/AUTHENTICATION_MATERIAL_IN_EVIDENCE/);
  }finally{await rm(f.root,{recursive:true,force:true})}
});
test('unlabeled corpus-style evidence cannot be packaged as a supplementary native probe',async()=>{
  assert.equal(typeof pack.packageEvidence,'function');const f=await fixture();
  try{await writeFile(join(f.output,'run.json'),JSON.stringify(identity));await assert.rejects(()=>pack.packageEvidence(f),/SUPPLEMENTARY_LABEL_REQUIRED/)}
  finally{await rm(f.root,{recursive:true,force:true})}
});
test('a changed native MP4 cannot be sealed under a stale successful result hash',async()=>{
  assert.equal(typeof pack.packageEvidence,'function');const f=await fixture();
  try{await writeFile(join(f.output,'rul01','native-clip.mp4'),Buffer.alloc(8192,74));await assert.rejects(()=>pack.packageEvidence(f),/NATIVE_EXPORT_HASH_MISMATCH/)}
  finally{await rm(f.root,{recursive:true,force:true})}
});
