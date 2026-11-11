import {createHash} from 'node:crypto';
import {createReadStream,constants} from 'node:fs';
import {readFile,lstat,mkdir,copyFile,rm,realpath} from 'node:fs/promises';
import {basename,dirname,join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {gzipSync,gunzipSync} from 'node:zlib';
import {seal,open,keyHash} from './crypto.mjs';
import {nativeIdentity,contextFor,REPOSITORY,BRANCH} from './native-context.mjs';

const execute=promisify(execFile);
export const MAX_INPUT_BYTES=16*1024*1024;
export const MAX_ENVELOPE_BYTES=850000;
const HASH=/^[a-f0-9]{64}$/;
export const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function fileHash(path){const h=createHash('sha256');for await(const block of createReadStream(path))h.update(block);return h.digest('hex')}
const requireCondition=(condition,code)=>{if(!condition)throw Error(code)};
function parse(bytes,code){try{return JSON.parse(bytes)}catch{throw Error(code)}}
function safeSourceName(name){
  requireCondition(typeof name==='string'&&name.length>0&&Buffer.byteLength(name)<=240&&name===basename(name)&&
    !/[\\/\x00-\x1f\x7f]/.test(name)&&name!=='.'&&name!=='..'&&/\.(mp4|m4v|mov|webm)$/i.test(name),'UNSAFE_SOURCE_NAME');
}
function sourceURL(value){
  let url;try{url=new URL(value)}catch{throw Error('INVALID_SOURCE_URL')}
  requireCondition(url.protocol==='https:'&&!!url.hostname&&!url.username&&!url.password&&!url.hash,'INVALID_SOURCE_URL');
  return url.href;
}
export function clipSpec(clip){
  return Object.fromEntries(['id','title','start','end','segments','layout','focusX','theme','speakerPreset','captions','scene','scenes'].filter(k=>clip[k]!==undefined).map(k=>[k,clip[k]]));
}
export function validateInput(payload,identity){
  const id=nativeIdentity(identity);
  requireCondition(payload?.version===1&&payload.suite==='native_export_probe','INVALID_NATIVE_INPUT');
  const origin=payload.origin||{},source=payload.source||{},login=payload.credentials||{};
  requireCondition(origin.caseId===id.caseId,'SOURCE_CASE_MISMATCH');
  requireCondition(/^[1-9]\d*$/.test(String(origin.runId||''))&&/^[1-9]\d*$/.test(String(origin.runAttempt||''))&&
    HASH.test(origin.receiptSha256||'')&&HASH.test(origin.projectSha256||'')&&Array.isArray(origin.artifactIds)&&origin.artifactIds.length>0&&
    origin.artifactIds.every(v=>/^[1-9]\d*$/.test(String(v)))&&new Set(origin.artifactIds.map(String)).size===origin.artifactIds.length,'INVALID_ORIGIN_PROVENANCE');
  requireCondition(/^[a-f0-9]{40}$/.test(origin.siteCommit||''),'INVALID_PRIMARY_SITE_COMMIT');
  requireCondition(HASH.test(origin.assignmentStateSha256||'')&&String(origin.assignmentRunId)===String(origin.runId)&&
    String(origin.assignmentRunAttempt)===String(origin.runAttempt)&&origin.assignmentCaseId===origin.caseId,'PRIMARY_ASSIGNMENT_MISMATCH');
  requireCondition(typeof origin.projectPath==='string'&&origin.projectPath.startsWith(id.caseId+'/')&&
    origin.projectPath===id.caseId+'/'+basename(origin.projectPath)&&/\.json$/i.test(origin.projectPath),'INVALID_PROJECT_PATH');
  safeSourceName(source.name);sourceURL(source.url);
  requireCondition(Number.isSafeInteger(source.bytes)&&source.bytes>0&&source.bytes<=2_000_000_000&&HASH.test(source.sha256||'')&&
    Number.isSafeInteger(source.modified)&&source.modified>0&&source.modified<=8.64e15&&
    Number.isFinite(source.durationSeconds)&&source.durationSeconds>=7200&&source.durationSeconds<=10800,'INVALID_SOURCE_METADATA');
  requireCondition(typeof login.email==='string'&&/^\S+@\S+\.\S+$/.test(login.email)&&login.email.length<=254&&
    typeof login.password==='string'&&login.password.length>=8&&login.password.length<=1024&&!/[\r\n]/.test(login.password),'INVALID_LOGIN_PAYLOAD');
  requireCondition(typeof payload.projectBase64==='string'&&payload.projectBase64.length<=MAX_INPUT_BYTES,'PROJECT_TOO_LARGE');
  const projectBytes=Buffer.from(payload.projectBase64,'base64');
  requireCondition(projectBytes.length>0&&projectBytes.toString('base64')===payload.projectBase64,'INVALID_PROJECT_ENCODING');
  requireCondition(sha256(projectBytes)===origin.projectSha256,'PROJECT_HASH_MISMATCH');
  const project=parse(projectBytes,'INVALID_PROJECT_JSON');
  requireCondition([1,2].includes(project.schema)&&Array.isArray(project.clips)&&Array.isArray(project.chunks)&&project.chunks.length>0&&
    Number.isFinite(project.duration)&&project.duration>=7200&&project.duration<=10800&&Math.abs(project.duration-source.durationSeconds)<=2,'INVALID_LONG_PROJECT');
  requireCondition(project.source?.name===source.name&&project.source?.size===source.bytes&&project.source?.modified===source.modified,'SOURCE_METADATA_MISMATCH');
  requireCondition(typeof payload.selectedClipId==='string'&&payload.selectedClipId.length>0&&payload.selectedClipId!=='draft-1','INVALID_SELECTED_CLIP');
  const matches=project.clips.map((clip,index)=>({clip,index})).filter(row=>String(row.clip?.id)===payload.selectedClipId);
  requireCondition(matches.length===1,'CLIP_ID_NOT_UNIQUE');
  const {clip,index:clipIndex}=matches[0];
  requireCondition(!clip.candidate&&!(clip.editorialStatus==='needs-more-context'&&clip.status!=='approved'),'CLIP_NOT_EXPORTABLE');
  const segments=Array.isArray(clip.segments)&&clip.segments.length?clip.segments:[{start:clip.start,end:clip.end}];
  requireCondition(segments.every(p=>Number.isFinite(p?.start)&&Number.isFinite(p?.end)&&p.start>=0&&p.end>p.start&&p.end<=project.duration),'INVALID_RETAINED_EDL');
  const outputSeconds=segments.reduce((sum,p)=>sum+p.end-p.start,0);
  requireCondition(outputSeconds>=300,'CLIP_TOO_SHORT');
  requireCondition(outputSeconds<=10800,'CLIP_TOO_LONG');
  return {identity:id,project,projectBytes,clip,clipIndex,segments,outputSeconds};
}

export function encodeInput(payload,descriptor){
  requireCondition(descriptor?.version===1&&descriptor.context?.purpose==='native-input','INVALID_HANDOFF_DESCRIPTOR');
  const expires=Date.parse(descriptor.expiresAt);
  requireCondition(Number.isFinite(expires)&&expires>Date.now(),'HANDOFF_EXPIRED');
  requireCondition(keyHash(descriptor.publicKeyPem||'')===descriptor.keySha256,'HANDOFF_KEY_MISMATCH');
  const context=contextFor('native-input',descriptor.context);validateInput(payload,context);
  const plain=Buffer.from(JSON.stringify(payload));requireCondition(plain.length<=MAX_INPUT_BYTES,'INPUT_TOO_LARGE');
  const compressed=gzipSync(plain);plain.fill(0);
  try{
    requireCondition(compressed.length<=600000,'COMPRESSED_INPUT_TOO_LARGE');
    const envelope=seal(compressed,descriptor.publicKeyPem,context);
    requireCondition(Buffer.byteLength(JSON.stringify(envelope))<=MAX_ENVELOPE_BYTES,'ENVELOPE_TOO_LARGE');
    return envelope;
  }finally{compressed.fill(0)}
}
export function decodeInput(envelope,privateKey,expectedContext){
  const context=contextFor('native-input',expectedContext);
  requireCondition(expectedContext.purpose==='native-input','INVALID_ENCRYPTION_PURPOSE');
  requireCondition(Buffer.byteLength(JSON.stringify(envelope))<=MAX_ENVELOPE_BYTES,'ENVELOPE_TOO_LARGE');
  const compressed=open(envelope,privateKey,context);let plain;
  try{
    try{plain=gunzipSync(compressed,{maxOutputLength:MAX_INPUT_BYTES})}catch(error){throw Error(error.code==='ERR_BUFFER_TOO_LARGE'?'INPUT_TOO_LARGE':'INVALID_COMPRESSED_INPUT')}
    const payload=parse(plain,'INVALID_INPUT_JSON');validateInput(payload,context);return payload;
  }finally{compressed.fill(0);plain?.fill(0)}
}

async function regular(path){const st=await lstat(path);requireCondition(st.isFile()&&!st.isSymbolicLink(),'INPUT_NOT_REGULAR_FILE');return st}
async function verifiedMember(path,record,code){
  const st=await regular(path);requireCondition(record&&record.bytes===st.size&&HASH.test(record.sha256||'')&&await fileHash(path)===record.sha256,code);
  return readFile(path);
}
async function assignmentFromState(path,identity){
  await regular(path);const bytes=await readFile(path),state=parse(bytes,'INVALID_ORCHESTRATOR_STATE');
  const selected=state.primary_case_runs?.[identity.caseId];
  const run=selected&&typeof selected==='object'?(selected.run_id??selected.runId):selected;
  const attempt=selected&&typeof selected==='object'?(selected.run_attempt??selected.runAttempt):null;
  requireCondition(String(run)===identity.runId&&(attempt==null||String(attempt)===identity.runAttempt),'SELECTED_CASE_NOT_PRIMARY');
  return {assignmentStateSha256:sha256(bytes),assignmentRunId:identity.runId,assignmentRunAttempt:identity.runAttempt,
    assignmentCaseId:identity.caseId,assignmentCheckedAt:new Date().toISOString(),assignmentAttemptSource:attempt==null?'authenticated_receipt':'orchestrator_state'};
}
export async function buildInput(receiptPath,projectPath,selectedClipId,url,credentialPath,statePath='/workspace/shared/examclips-long-audit/state.json'){
  const receiptBytes=await readFile(receiptPath),receipt=parse(receiptBytes,'INVALID_RECEIPT');
  requireCondition(receipt.gcm_authenticated===true&&receipt.encrypted_context_verified===true&&receipt.context?.purpose==='evidence'&&
    receipt.context.repository===REPOSITORY&&receipt.context.branch===BRANCH,'UNAUTHENTICATED_RECEIPT');
  const identity=nativeIdentity(receipt.context);
  requireCondition(String(receipt.run_id)===identity.runId&&String(receipt.run_attempt)===identity.runAttempt&&receipt.case_id===identity.caseId,'RECEIPT_IDENTITY_MISMATCH');
  await assignmentFromState(statePath,identity);
  const caseDir=await realpath(receipt.case_directory),projectResolved=resolve(projectPath);
  requireCondition(dirname(projectResolved)===caseDir,'PROJECT_OUTSIDE_AUTHENTICATED_CASE');
  const projectKey=identity.caseId+'/'+basename(projectResolved),inventory=receipt.file_inventory||{};
  const projectBytes=await verifiedMember(projectResolved,inventory[projectKey],'PROJECT_HASH_MISMATCH');
  const project=parse(projectBytes,'INVALID_PROJECT_JSON');
  const sourceKey=identity.caseId+'/original-source.mp4',sourceRecord=inventory[sourceKey],sourcePath=join(caseDir,'original-source.mp4');
  const sourceStat=await regular(sourcePath);
  requireCondition(sourceRecord&&sourceRecord.bytes===sourceStat.size&&await fileHash(sourcePath)===sourceRecord.sha256,'SOURCE_HASH_MISMATCH');
  const sourceJSON=await verifiedMember(join(caseDir,'source.json'),inventory[identity.caseId+'/source.json'],'SOURCE_METADATA_HASH_MISMATCH');
  const sourceInfo=parse(sourceJSON,'INVALID_SOURCE_METADATA_JSON');
  const primaryRun=parse(await verifiedMember(join(dirname(caseDir),'run.json'),inventory['run.json'],'PRIMARY_RUN_HASH_MISMATCH'),'INVALID_PRIMARY_RUN_JSON');
  const siteCommit=primaryRun.buildBefore?.data?.commit;
  requireCondition(String(primaryRun.runId)===identity.runId&&primaryRun.caseId===identity.caseId&&
    /^[a-f0-9]{40}$/.test(siteCommit||'')&&primaryRun.buildAfter?.data?.commit===siteCommit&&!primaryRun.buildChanged,'PRIMARY_BUILD_NOT_STABLE');
  const credentialStat=await regular(credentialPath);requireCondition(!(credentialStat.mode&0o077)&&credentialStat.size<=65536,'LOGIN_FILE_MUST_BE_PRIVATE');
  const credentials=parse(await readFile(credentialPath),'INVALID_LOGIN_JSON');
  // Re-read the orchestrator's current assignment after potentially long source
  // hashing. Other case updates are harmless; a changed selected case is not.
  const assignment=await assignmentFromState(statePath,identity);
  const payload={version:1,suite:'native_export_probe',credentials:{email:credentials.email,password:credentials.password},
    origin:{runId:identity.runId,runAttempt:identity.runAttempt,caseId:identity.caseId,receiptSha256:sha256(receiptBytes),projectPath:projectKey,
      projectSha256:sha256(projectBytes),artifactIds:(receipt.artifacts||[]).map(p=>String(p.artifact_id)),siteCommit,...assignment},
    source:{url:sourceURL(url),name:project.source?.name,bytes:sourceRecord.bytes,modified:project.source?.modified,sha256:sourceRecord.sha256,durationSeconds:Number(sourceInfo.duration_sec)},
    projectBase64:projectBytes.toString('base64'),selectedClipId};
  validateInput(payload,identity);return payload;
}

export async function stageSource(sourcePath,destinationDirectory,metadata){
  safeSourceName(metadata.name);
  const source=await regular(sourcePath);requireCondition(source.size===metadata.bytes,'SOURCE_SIZE_MISMATCH');
  requireCondition(HASH.test(metadata.sha256||'')&&Number.isSafeInteger(metadata.modified)&&metadata.modified>0,'INVALID_SOURCE_METADATA');
  await mkdir(destinationDirectory,{recursive:true,mode:0o700});
  const directory=await lstat(destinationDirectory);requireCondition(directory.isDirectory()&&!directory.isSymbolicLink(),'UNSAFE_SOURCE_DIRECTORY');
  const target=join(resolve(destinationDirectory),metadata.name);let created=false;
  try{
    await copyFile(sourcePath,target,constants.COPYFILE_EXCL);created=true;
    requireCondition(await fileHash(target)===metadata.sha256,'SOURCE_HASH_MISMATCH');
    // Python's integer-nanosecond utime avoids rounding an epoch-sized JS float
    // down by a microsecond and thus changing Chrome's integer lastModified.
    await execute('python3',['-c','import os,sys; n=int(sys.argv[2])*1000000; os.utime(sys.argv[1],ns=(n,n))',target,String(metadata.modified)],{timeout:10000,maxBuffer:4096});
    return target;
  }catch(error){if(created)await rm(target,{force:true});throw error}
}
