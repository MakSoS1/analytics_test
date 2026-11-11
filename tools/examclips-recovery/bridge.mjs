import {mkdir,readFile,writeFile,rm,stat,readdir,lstat} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {resolve,join,dirname,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync,createPublicKey,createHash,createCipheriv,randomBytes} from 'node:crypto';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {spawn} from 'node:child_process';
import {open,seal,keyHash} from '../examclips-audit/crypto.mjs';
import {REPO,BRANCH,ROSTERS,requireIdentity,validateRequest,targetFor,canonical,safeRelative,acceptableSequence,allowedReference} from './protocol.mjs';
import {ingestCase} from './ingest.mjs';
import {createPublicInputReader} from './public-input.mjs';
const HERE=dirname(fileURLToPath(import.meta.url)),identity=requireIdentity(process.env);
const prefix='.audit-recovery/'+identity.runId+'/'+identity.runAttempt+'/'+identity.caseId;
const privateRoot=join(process.env.RUNNER_TEMP,'examclips-review-'+identity.runId+'-'+identity.runAttempt+'-'+identity.caseId);
const token=process.env.GITHUB_TOKEN;
if(!token)throw Error('GITHUB_TOKEN_MISSING');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const context=purpose=>({purpose,...identity});
const knownFixture={fixture:'examclips-review-bridge',bytes:[0,1,127,128,255],version:1};
let replyKey=null,current=null,diagnostic=null,sequence=0;
async function gh(path,options={}){
 const response=await fetch('https://api.github.com'+path,{method:options.method||'GET',headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},body:options.body===undefined?undefined:JSON.stringify(options.body),signal:AbortSignal.timeout(90000)});
 if(!response.ok){const e=Error('GITHUB_HTTP_'+response.status);e.status=response.status;throw e;}
 return response.status===204?null:response.json();
}
const readPublic=createPublicInputReader({repository:REPO,branch:BRANCH,prefix,token,
 onObservation:value=>{if(value.status!==304)console.log('RECOVERY_INPUT_TRANSPORT '+JSON.stringify(value));}
});
async function publish(entries,message){
 for(const entry of entries)if(!entry.path.startsWith(prefix+'/'))throw Error('PUBLIC_OUTPUT_PATH_ESCAPE');
 const prepared=[];
 for(const entry of entries){if(entry.content.length>200000){const blob=await gh('/repos/'+REPO+'/git/blobs',{method:'POST',body:{content:entry.content,encoding:'utf-8'}});prepared.push({path:entry.path,mode:'100644',type:'blob',sha:blob.sha});}else prepared.push({path:entry.path,mode:'100644',type:'blob',content:entry.content});}
 for(let trial=0;trial<12;trial++){
  const ref=await gh('/repos/'+REPO+'/git/ref/heads/'+BRANCH);
  const parent=ref.object.sha,commit=await gh('/repos/'+REPO+'/git/commits/'+parent);
  const tree=await gh('/repos/'+REPO+'/git/trees',{method:'POST',body:{base_tree:commit.tree.sha,tree:prepared}});
  const next=await gh('/repos/'+REPO+'/git/commits',{method:'POST',body:{message,tree:tree.sha,parents:[parent]}});
  try{await gh('/repos/'+REPO+'/git/refs/heads/'+BRANCH,{method:'PATCH',body:{sha:next.sha,force:false}});return next.sha;}
  catch(error){if(![409,422].includes(error.status)||trial===11)throw error;await pause(1500);}
 }
}
function replyEnvelope(value,replyContext,key=replyKey){
 if(!key||key.length!==32)throw Error('REPLY_KEY_UNAVAILABLE');
 const plaintext=Buffer.from(JSON.stringify(value)),iv=randomBytes(12);
 const metadata={version:1,algorithm:'AES-256-GCM',context:replyContext,plaintextBytes:plaintext.length,sha256:sha(plaintext)};
 const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(canonical(metadata)));
 const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
 return {...metadata,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')};
}
async function reply(seq,value){
 const replyContext={...context('review-reply'),sequence:seq,key:value.key??null};
 const envelope=replyEnvelope(value,replyContext);
 const responsePath=prefix+'/responses/'+String(seq).padStart(5,'0'),entries=[],characters=envelope.ciphertext.length;
 if(characters>600000){
  envelope.ciphertextParts=[];
  for(let start=0,index=1;start<characters;start+=600000,index++){
   const piece=envelope.ciphertext.slice(start,start+600000),path=responsePath+'-p'+String(index).padStart(4,'0')+'.json';
   envelope.ciphertextParts.push({path,index,characters:piece.length,sha256:sha(piece)});
   entries.push({path,content:JSON.stringify({index,ciphertext:piece})});
  }
  delete envelope.ciphertext;
 }
 entries.push({path:responsePath+'.json',content:JSON.stringify(envelope)});
 await publish(entries,'Publish encrypted review response '+identity.runId+' '+identity.caseId+' '+seq);
 console.log('REVIEW_RESPONSE '+JSON.stringify({lane:identity.caseId,sequence:seq,status:value.status,key:value.key??null,encryptedCharacters:characters,parts:envelope.ciphertextParts?.length??1}));
}
async function waitInput(filename,expectedContext,privateKey,timeoutMs){
 const expires=Date.now()+timeoutMs;
 while(Date.now()<expires){
  let value=null;try{value=await readPublic(prefix+'/'+filename);}catch(error){if(!/^PUBLIC_READ_HTTP_5/.test(error.message))throw error;}
  if(value){const bytes=open(value,privateKey,expectedContext);return JSON.parse(bytes.toString('utf8'));}
  await pause(5000);
 }
 throw Error('PRIVATE_INPUT_TIMEOUT');
}
async function executePrivate(command,args,stdin,pathPrefix,{timeout=600000}={}){
 const output=join(privateRoot,pathPrefix+'.stdout'),error=join(privateRoot,pathPrefix+'.stderr');
 const out=createWriteStream(output,{mode:0o600}),err=createWriteStream(error,{mode:0o600});
 const child=spawn(command,args,{stdio:['pipe','pipe','pipe'],env:{...process.env,DEBUG:'',PYTHONUNBUFFERED:'1'}});
 child.stdout.pipe(out);child.stderr.pipe(err);
 child.stdin.end(stdin===null?undefined:stdin);
 const timer=setTimeout(()=>child.kill('SIGKILL'),timeout);
 const code=await new Promise((res,rej)=>{child.once('error',rej);child.once('close',res);}).finally(()=>clearTimeout(timer));
 await Promise.all([new Promise(r=>out.end(r)),new Promise(r=>err.end(r))]);
 return {code,output,error};
}
async function downloadArtifact(id,destination){
 let url='https://api.github.com/repos/'+REPO+'/actions/artifacts/'+id+'/zip',response;
 for(let i=0;i<5;i++){
  response=await fetch(url,{headers:i===0?{Authorization:'Bearer '+token,Accept:'application/vnd.github+json'}:{},redirect:'manual',signal:AbortSignal.timeout(90000)});
  if([301,302,303,307,308].includes(response.status)){
   const next=new URL(response.headers.get('location'),url);
   if(next.protocol!=='https:'||!/(?:^|\.)(?:github\.com|githubusercontent\.com|blob\.core\.windows\.net)$/.test(next.hostname))throw Error('UNEXPECTED_ARTIFACT_REDIRECT');
   url=next.href;continue;
  }
  if(!response.ok||!response.body)throw Error('ARTIFACT_DOWNLOAD_FAILED');
  await pipeline(Readable.fromWeb(response.body),createWriteStream(destination,{mode:0o600}));return;
 }
 throw Error('ARTIFACT_REDIRECT_LIMIT');
}
async function inventory(){
 const records=[];
 async function visit(dir){
  for(const entry of await readdir(dir,{withFileTypes:true})){
   const path=join(dir,entry.name),rel=relative(current.evidence,path).split('\\').join('/');
   if(entry.isSymbolicLink())throw Error('REVIEW_SYMLINK');
   if(entry.isDirectory())await visit(path);
   else if(entry.isFile()){const st=await stat(path);records.push({path:rel,bytes:st.size,reviewable:/\.(json|jsonl|txt|srt|png|jpg|jpeg|csv)$/i.test(rel),privateBrowserEvidence:/technical-ui|screenshot|browser/i.test(rel)});}
  }
 }
 await visit(current.evidence);return records;
}
async function readSelected(paths){
 let total=0;const records=[];
 for(const rel of paths){
  safeRelative(rel);const path=resolve(current.evidence,rel);
  if(!path.startsWith(current.evidence+'/'))throw Error('REVIEW_PATH_ESCAPE');
  const st=await lstat(path);if(!st.isFile()||st.isSymbolicLink())throw Error('REVIEW_FILE_NOT_REGULAR');
  total+=st.size;if(st.size>8*1024**2||total>12*1024**2)throw Error('REVIEW_PACKET_TOO_LARGE');
  const data=await readFile(path);
  records.push({path:rel,bytes:data.length,sha256:sha(data),mime:/\.png$/i.test(rel)?'image/png':/\.jpe?g$/i.test(rel)?'image/jpeg':'application/octet-stream',base64:data.toString('base64')});
 }
 return records;
}
function diagnosticStatus(){
 if(!diagnostic)return {started:false};
 return {started:true,running:diagnostic.code===null,exitCode:diagnostic.code,startedAt:diagnostic.startedAt,finishedAt:diagnostic.finishedAt??null};
}
async function operation(request){
 if(request.operation==='finish')return {status:'finished'};
 const target=targetFor(identity.caseId,request.key);
 if(request.operation==='ingest'){
  if(diagnostic?.code===null)throw Error('DIAGNOSTIC_STILL_RUNNING');
  if(current?.receipt.target.key===target.key)return {status:'ready',key:target.key,receipt:current.receipt,inventory:await inventory(),reused:true};
  if(current){await rm(current.root,{recursive:true});current=null;diagnostic=null;}
  const root=join(privateRoot,'case-'+target.key);
  await rm(root,{recursive:true,force:true});
  current=await ingestCase({target,root,privateKey:await readFile(join(privateRoot,'recovery.pem'),'utf8'),gh,downloadArtifact});
  return {status:'ready',key:target.key,receipt:current.receipt,inventory:await inventory()};
 }
 if(!current||current.receipt.target.key!==target.key)throw Error('CASE_NOT_CURRENT');
 if(request.operation==='inventory')return {status:'ready',key:target.key,inventory:await inventory(),diagnostics:diagnosticStatus()};
 if(request.operation==='reference'){
  let url=request.url,response=null;
  for(let redirects=0;redirects<5;redirects++){
   if(!allowedReference(url))throw Error('UNAPPROVED_REFERENCE_REDIRECT');
   response=await fetch(url,{redirect:'manual',signal:AbortSignal.timeout(60000)});
   if([301,302,303,307,308].includes(response.status)){url=new URL(response.headers.get('location'),url).href;continue;}break;
  }
  if(!response?.ok||!response.body)throw Error('PUBLIC_REFERENCE_FAILED');
  const chunks=[];let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;if(bytes>8*1024**2)throw Error('REFERENCE_SIZE_LIMIT');chunks.push(Buffer.from(chunk));}
  const data=Buffer.concat(chunks),file=join(current.caseDir,'reference-'+sha(request.url).slice(0,16)+'.txt');
  await writeFile(file,data,{mode:0o600});
  return {status:'ready',key:target.key,reference:{requestedUrl:request.url,finalUrl:url,contentType:response.headers.get('content-type'),sha256:sha(data),bytes},files:await readSelected([relative(current.evidence,file)])};
 }
 if(request.operation==='files')return {status:'ready',key:target.key,files:await readSelected(request.paths)};
 if(request.operation==='frame'){
  const result=await executePrivate('python3',[join(HERE,'media.py'),'frame',current.caseDir,request.path,String(request.seconds)],null,'frame-'+request.sequence,{timeout:120000});
  if(result.code!==0)throw Error('FRAME_EXTRACTION_FAILED');
  const record=JSON.parse(await readFile(result.output,'utf8'));
  return {status:'ready',key:target.key,frame:record,files:await readSelected([target.id+'/'+record.image_file])};
 }
 if(request.operation==='diagnostics-start'){
  if(target.native)throw Error('PRIMARY_MEDIA_REQUIRED');
  if(diagnostic)return {status:'ready',key:target.key,diagnostics:diagnosticStatus()};
  const log=join(current.caseDir,'recovery-diagnostic.txt'),err=join(current.caseDir,'recovery-diagnostic-error.txt');
  const out=createWriteStream(log,{mode:0o600}),error=createWriteStream(err,{mode:0o600});
  const child=spawn('python3',[join(HERE,'media.py'),'diagnostics',current.caseDir],{stdio:['ignore','pipe','pipe'],env:{...process.env,OMP_NUM_THREADS:'2',OPENBLAS_NUM_THREADS:'1'}});
  child.stdout.pipe(out);child.stderr.pipe(error);
  const active={child,code:null,startedAt:new Date().toISOString()};diagnostic=active;
  child.once('error',()=>{active.code=-1;active.finishedAt=new Date().toISOString();});
  child.once('close',code=>{active.code=code??-1;active.finishedAt=new Date().toISOString();out.end();error.end();});
  return {status:'started',key:target.key,diagnostics:diagnosticStatus()};
 }
 if(request.operation==='diagnostics-status')return {status:'ready',key:target.key,diagnostics:diagnosticStatus()};
 throw Error('UNSUPPORTED_REQUEST');
}
async function main(){
 await mkdir(privateRoot,{recursive:true,mode:0o700});
 const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:4096,publicExponent:65537,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 await writeFile(join(privateRoot,'ephemeral.pem'),privateKey,{mode:0o600});
 const bundle=await readFile(join(HERE,'client-bundle.js'),'utf8');
 const descriptor={version:1,...identity,purpose:'review-recovery-input',sourceCommit:process.env.GITHUB_SHA,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+45*60000).toISOString(),publicKey,keySha256:keyHash(publicKey),bundleSha256:sha(bundle),roster:ROSTERS[identity.caseId],fixture:knownFixture};
 await publish([{path:prefix+'/public.json',content:JSON.stringify(descriptor,null,2)},{path:prefix+'/client-bundle.js',content:bundle}],'Publish recovery public key and tested crypto bundle '+identity.runId+' '+identity.caseId);
 console.log('RECOVERY_PUBLIC_READY '+JSON.stringify({lane:identity.caseId,runId:identity.runId,keySha256:descriptor.keySha256,bundleSha256:descriptor.bundleSha256}));
 const fixture=await waitInput('fixture.json',context('review-recovery-fixture'),privateKey,45*60000);
 if(canonical(fixture)!==canonical(knownFixture))throw Error('PUBLIC_FIXTURE_MISMATCH');
 const fixtureReply=replyEnvelope({fixturePassed:true,...knownFixture},context('review-fixture-reply'),Buffer.alloc(32,19));
 await publish([{path:prefix+'/fixture-result.json',content:JSON.stringify(fixtureReply)}],'Publish recovery interoperability fixture '+identity.runId+' '+identity.caseId);
 console.log('RECOVERY_FIXTURE_PASSED '+identity.caseId);
 const payload=await waitInput('input.json',context('review-recovery-input'),privateKey,45*60000);
 if(payload.version!==1||payload.bundleSha256!==descriptor.bundleSha256||payload.transfer?.library_file_id!=='libfile_fccc5b51041c81919a098baea581bab8'||!payload.transfer.download_url||payload.transfer.workspace_path)throw Error('INVALID_RECOVERY_INPUT');
 replyKey=Buffer.from(payload.replyKey||'','base64');if(replyKey.length!==32)throw Error('INVALID_REPLY_KEY');
 const helperDir=join(privateRoot,'library-helpers');await mkdir(helperDir,{mode:0o700});
 for(const name of ['library_file_transfer.py','library_hosted_apps.py']){
  const item=payload.helpers?.[name];if(!item||typeof item.contents!=='string'||sha(item.contents)!==item.sha256)throw Error('LIBRARY_HELPER_INTEGRITY_FAILED');
  await writeFile(join(helperDir,name),item.contents,{mode:0o600});
 }
 const transfer=await executePrivate('python3',[join(helperDir,'library_file_transfer.py'),'materialize',join(privateRoot,'recovery.pem')],JSON.stringify(payload.transfer),'materialize',{timeout:180000});
 if(transfer.code!==0){await reply(0,{status:'infrastructure_failure',stage:'library_materialize',stdout:await readFile(transfer.output,'utf8'),stderr:await readFile(transfer.error,'utf8')});throw Error('LIBRARY_MATERIALIZATION_FAILED');}
 const recovered=await readFile(join(privateRoot,'recovery.pem'),'utf8'),pub=createPublicKey(recovered).export({type:'spki',format:'pem'});
 const expected=await readFile(resolve(HERE,'../examclips-audit/evidence-recipient.pub.pem'),'utf8');
 if(keyHash(pub)!==keyHash(expected))throw Error('RECOVERY_KEY_FINGERPRINT_MISMATCH');
 payload.transfer=null;payload.helpers=null;payload.replyKey=null;
 await rm(join(privateRoot,'ephemeral.pem'),{force:true});
 const backup=seal(Buffer.from(JSON.stringify({version:1,identity,replyKey:replyKey.toString('base64'),createdAt:new Date().toISOString()})),expected,context('review-reply-key-backup'));
 await publish([{path:prefix+'/reply-key-backup.json',content:JSON.stringify(backup)}],'Preserve encrypted review reply key '+identity.runId+' '+identity.caseId);
 await reply(0,{status:'controller_ready',lane:identity.caseId,materialized:true,recoveryFingerprint:keyHash(pub),roster:ROSTERS[identity.caseId]});
 const deadline=Date.now()+260*60000;
 while(Date.now()<deadline){
  const request=await readPublic(prefix+'/request.json');
  if(!request||request.sequence<=sequence){await pause(5000);continue;}
  if(!acceptableSequence(sequence,request.sequence)){await pause(5000);continue;}
  try{
   validateRequest(request,identity.caseId,sequence+1);
   console.log('REVIEW_REQUEST_ACCEPTED '+JSON.stringify({lane:identity.caseId,sequence:request.sequence,operation:request.operation,key:request.key??null,at:new Date().toISOString()}));
   const result=await operation(request);sequence=request.sequence;
   await reply(sequence,result);
   if(request.operation==='finish')break;
  }catch(error){
   sequence=request.sequence;
   await reply(sequence,{status:'operation_failed',key:request.key??null,code:/^[A-Z][A-Z0-9_]{2,100}$/.test(error.message||'')?error.message:'RECOVERY_OPERATION_FAILED',detail:String(error.stack||error)});
  }
 }
 if(diagnostic?.code===null){diagnostic.child.kill('SIGTERM');await pause(1500);}
}
try{await main();}
catch(error){console.error('RECOVERY_STOPPED '+(/^[A-Z][A-Z0-9_]{2,100}$/.test(error.message||'')?error.message:'UNCLASSIFIED_INFRASTRUCTURE_FAILURE'));process.exitCode=1;}
finally{if(diagnostic?.code===null)diagnostic.child.kill('SIGKILL');if(replyKey)replyKey.fill(0);await rm(privateRoot,{recursive:true,force:true});}
