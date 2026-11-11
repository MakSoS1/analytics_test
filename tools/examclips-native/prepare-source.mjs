import {readFile,mkdir,writeFile,rm,statfs,stat,appendFile} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {Readable,Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {join,resolve} from 'node:path';
import {stageSource} from './input.mjs';
import {identityFromEnv,safeError} from './native-context.mjs';
const execute=promisify(execFile);

async function main(){
  const identity=identityFromEnv(),root=resolve(process.env.AUDIT_ROOT),out=join(resolve(process.env.AUDIT_OUT),identity.caseId);
  let input;try{input=JSON.parse(await readFile(process.env.NATIVE_INPUT_FILE,'utf8'))}catch{throw Error('INVALID_NATIVE_INPUT_FILE')}
  if(input.origin?.caseId!==identity.caseId)throw Error('SOURCE_CASE_MISMATCH');
  const expected=input.source,url=new URL(expected.url);
  if(url.protocol!=='https:'||url.username||url.password)throw Error('INVALID_SOURCE_URL');
  if(!Number.isSafeInteger(expected.bytes)||expected.bytes<=0||expected.bytes>2_000_000_000)throw Error('INVALID_SOURCE_SIZE');
  await mkdir(root,{recursive:true,mode:0o700});await mkdir(out,{recursive:true,mode:0o700});
  const disk=await statfs(root);
  if(disk.bavail*disk.bsize<expected.bytes*2+3*1024**3)throw Error('INSUFFICIENT_SOURCE_STAGING_DISK');
  const incoming=join(root,'source-download.tmp'),h=createHash('sha256');let bytes=0;
  try{
    const response=await fetch(url,{headers:{'User-Agent':'ExamClips-authorized-native-export-probe'},signal:AbortSignal.timeout(12*60*1000)});
    if(!response.ok||new URL(response.url).protocol!=='https:'||!response.body)throw Error('SOURCE_FETCH_FAILED');
    const measure=new Transform({transform(block,encoding,callback){bytes+=block.length;if(bytes>expected.bytes){callback(Error('SOURCE_SIZE_MISMATCH'));return}h.update(block);callback(null,block)}});
    await pipeline(Readable.fromWeb(response.body),measure,createWriteStream(incoming,{flags:'wx',mode:0o600}));
    if(bytes!==expected.bytes||h.digest('hex')!==expected.sha256)throw Error('SOURCE_HASH_MISMATCH');
    const path=await stageSource(incoming,join(root,'original'),expected);await rm(incoming,{force:true});
    const {stdout}=await execute('ffprobe',['-v','error','-show_format','-show_streams','-of','json',path],{timeout:60000,maxBuffer:1024**2});
    let probe;try{probe=JSON.parse(stdout)}catch{throw Error('SOURCE_PROBE_FAILED')}
    const duration=Number(probe.format?.duration),kinds=new Set((probe.streams||[]).map(s=>s.codec_type));
    if(!Number.isFinite(duration)||duration<7200||duration>10800||Math.abs(duration-expected.durationSeconds)>2||!kinds.has('audio')||!kinds.has('video'))throw Error('SOURCE_DURATION_OR_TRACK_MISMATCH');
    const st=await stat(path);
    const record={...expected,duration_sec:duration,bytes:st.size,sha256:expected.sha256,restoredFilename:expected.name,restoredModifiedMilliseconds:st.mtimeMs,
      method:'Complete direct public source; exact authenticated primary-source SHA-256; separate staged copy with recorded name and mtime',
      primaryRun:input.origin.runId,primaryAttempt:input.origin.runAttempt,primaryCase:identity.caseId,
      streams:probe.streams.map(s=>Object.fromEntries(['codec_type','codec_name','width','height','duration','sample_rate','channels'].filter(k=>s[k]!==undefined).map(k=>[k,s[k]])))};
    await writeFile(join(out,'source.json'),JSON.stringify(record,null,2)+'\n',{mode:0o600});
    await appendFile(process.env.GITHUB_OUTPUT,'source_path='+path+'\n');
    console.log('NATIVE_SOURCE_VERIFIED '+JSON.stringify({caseId:identity.caseId,durationSeconds:duration,bytes:st.size,sha256:expected.sha256}));
  }finally{await rm(incoming,{force:true})}
}
main().catch(error=>{console.error(safeError(error));process.exitCode=1});
