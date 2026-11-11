import {mkdir,readFile,writeFile,readdir,lstat,rm,appendFile,statfs} from 'node:fs/promises';
import {resolve,join,dirname,basename} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {sealFile} from './crypto.mjs';
import {fileHash} from './input.mjs';
import {identityFromEnv,contextFor,safeError} from './native-context.mjs';
const HERE=dirname(fileURLToPath(import.meta.url)),execute=promisify(execFile);

function scan(value){
  if(!value||typeof value!=='object')return;
  for(const [key,child] of Object.entries(value)){
    if(/^(password|credentials?|cookies?|storageState|access_token|refresh_token|authorization|api_key)$/i.test(key))throw Error('AUTHENTICATION_MATERIAL_IN_EVIDENCE');
    scan(child);
  }
}
async function verifyTree(directory){
  let total=0;
  for(const entry of await readdir(directory,{withFileTypes:true})){
    if(entry.isSymbolicLink())throw Error('EVIDENCE_SYMLINK_REJECTED');
    if(/credential|password|cookie|storage.?state|profile|trace|\.har$/i.test(entry.name))throw Error('AUTHENTICATION_MATERIAL_IN_EVIDENCE');
    const path=join(directory,entry.name);
    if(entry.isDirectory()){total+=await verifyTree(path);continue}
    if(!entry.isFile()||!/^.+\.(json|jsonl|srt|png|mp4|txt)$/i.test(entry.name)||entry.name==='original-source.mp4')throw Error('UNEXPECTED_NATIVE_EVIDENCE_FILE');
    const st=await lstat(path);total+=st.size;
    if(/\.jsonl?$/i.test(entry.name)){
      if(st.size>32*1024**2)throw Error('EVIDENCE_JSON_TOO_LARGE');
      const content=await readFile(path,'utf8');
      try{if(entry.name.endsWith('.jsonl'))for(const line of content.split('\n').filter(Boolean))scan(JSON.parse(line));else scan(JSON.parse(content))}
      catch(error){if(error.message==='AUTHENTICATION_MATERIAL_IN_EVIDENCE')throw error;throw Error('EVIDENCE_JSON_INVALID')}
    }
  }
  return total;
}
export async function packageEvidence({output,artifact,privateRoot,publicKeyFile,identity,stepOutcomes={}}){
  const context=contextFor('evidence',identity),runPath=join(output,'run.json'),resultPath=join(output,identity.caseId,'result.json');
  const run=JSON.parse(await readFile(runPath,'utf8')),result=JSON.parse(await readFile(resultPath,'utf8'));
  for(const item of [run,result])if(item.auditKind!=='native_export_probe'||item.supplementary!==true||item.corpusCountIncrement!==0)throw Error('SUPPLEMENTARY_LABEL_REQUIRED');
  if(run.repository!==identity.repository||String(run.runId)!==identity.runId||String(run.runAttempt)!==identity.runAttempt||run.caseId!==identity.caseId||result.id!==identity.caseId)throw Error('EVIDENCE_IDENTITY_MISMATCH');
  for(const clip of result.clips||[])if(clip.exportStatus==='saved_native'){
    if(typeof clip.file!=='string'||basename(clip.file)!==clip.file)throw Error('INVALID_NATIVE_EXPORT_FILENAME');
    const path=join(output,identity.caseId,clip.file),st=await lstat(path);
    if(!st.isFile()||st.isSymbolicLink()||st.size!==clip.bytes||await fileHash(path)!==clip.sha256)throw Error('NATIVE_EXPORT_HASH_MISMATCH');
  }
  if(Object.keys(stepOutcomes).length){
    run.workflowStepOutcomes=stepOutcomes;
    if(result.status==='not_started'){
      result.status='workflow_failed_before_native_export';result.failedSetupStages=Object.entries(stepOutcomes).filter(([,value])=>['failure','cancelled'].includes(value)).map(([name])=>name);
      run.status=result.status;await writeFile(resultPath,JSON.stringify(result,null,2)+'\n',{mode:0o600});
    }
    await writeFile(runPath,JSON.stringify(run,null,2)+'\n',{mode:0o600});
  }
  const bytes=await verifyTree(output);await mkdir(artifact,{recursive:true,mode:0o700});await mkdir(privateRoot,{recursive:true,mode:0o700});
  const disk=await statfs(privateRoot);if(disk.bavail*disk.bsize<2*bytes+256*1024**2)throw Error('INSUFFICIENT_EVIDENCE_PACKAGING_DISK');
  const key=await readFile(publicKeyFile,'utf8'),zip=join(privateRoot,'evidence.zip'),cipher=join(artifact,'evidence.enc');
  try{
    const script="import pathlib,sys,zipfile\nroot=pathlib.Path(sys.argv[1])\nwith zipfile.ZipFile(sys.argv[2],'w',compression=zipfile.ZIP_STORED,allowZip64=True) as archive:\n for item in sorted(root.rglob('*')):\n  if item.is_file(): archive.write(item,item.relative_to(root))\n";
    await execute('python3',['-c',script,output,zip],{timeout:600000,maxBuffer:8192});
    const metadata=await sealFile(zip,cipher,key,context);await rm(zip,{force:true});
    const metadataPath=join(artifact,'encryption.json');await writeFile(metadataPath,JSON.stringify(metadata,null,2)+'\n',{mode:0o600});
    await execute('python3',[join(HERE,'split_evidence.py'),'split',cipher,metadataPath,artifact],{timeout:600000,maxBuffer:8192});
    const manifest=JSON.parse(await readFile(join(artifact,'parts.json'),'utf8'));
    await rm(cipher,{force:true});await rm(metadataPath,{force:true});return manifest;
  }finally{await rm(zip,{force:true})}
}
async function main(){
  const identity=identityFromEnv();
  const manifest=await packageEvidence({output:resolve(process.env.AUDIT_OUT),artifact:resolve(process.env.AUDIT_ARTIFACT),privateRoot:resolve(process.env.AUDIT_ROOT),
    publicKeyFile:join(HERE,'evidence-recipient.pub.pem'),identity,
    stepOutcomes:{tools:process.env.NATIVE_TOOLS_OUTCOME,native_picker_preflight:process.env.NATIVE_PREFLIGHT_OUTCOME,
      handoff:process.env.NATIVE_HANDOFF_OUTCOME,source:process.env.NATIVE_SOURCE_OUTCOME,browser:process.env.NATIVE_BROWSER_OUTCOME}});
  if(process.env.GITHUB_OUTPUT)await appendFile(process.env.GITHUB_OUTPUT,'parts='+manifest.parts.length+'\n');
  console.log('NATIVE_ENCRYPTED_EVIDENCE_READY '+JSON.stringify({runId:identity.runId,caseId:identity.caseId,parts:manifest.parts.length,bytes:manifest.bytes,auditKind:'native_export_probe',corpusCountIncrement:0}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{console.error(safeError(error));process.exitCode=1});
