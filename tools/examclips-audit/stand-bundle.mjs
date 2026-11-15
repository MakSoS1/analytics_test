import {createHash,createPublicKey} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {mkdir,readFile,writeFile,rm,stat,open as openFileHandle} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sealFile,openFile,keyHash} from './crypto.mjs';
import {identityFromEnv,contextFor} from './audit-context.mjs';
import {fetchArtifact,validatePayload,publicFailure} from './stand-policy.mjs';

const HERE=dirname(fileURLToPath(import.meta.url));
export async function digest(path){const hash=createHash('sha256');for await(const block of createReadStream(path))hash.update(block);return hash.digest('hex');}
export const bundleContext=identity=>contextFor('stand-bundle',{...identity,caseId:'bundle-prepare'});
const artifactRecord=config=>({id:config.artifact_id,bytes:config.artifact_bytes,sha256:config.artifact_sha256,sourceCommit:config.source_commit,ciRunId:config.ci_run_id});
async function assertArchive(path,config){if((await stat(path)).size!==config.artifact_bytes||await digest(path)!==config.artifact_sha256)throw Error('Private CI archive integrity mismatch');}

export async function encryptBundle(source,destination,recipient,identity,config){
 await assertArchive(source,config);await mkdir(destination,{recursive:true,mode:0o700});
 const file=join(destination,'bundle.enc');
 const metadata=await sealFile(source,file,recipient,bundleContext(identity));
 metadata.artifact=artifactRecord(config);metadata.ciphertextBytes=(await stat(file)).size;metadata.ciphertextSha256=await digest(file);
 await writeFile(join(destination,'bundle-encryption.json'),JSON.stringify(metadata,null,2)+'\n',{mode:0o600});
 return {bytes:metadata.ciphertextBytes,sha256:metadata.ciphertextSha256,recipientKeySha256:metadata.keySha256};
}

export async function decryptBundle(directory,destination,privateKey,identity,config){
 const metadata=JSON.parse(await readFile(join(directory,'bundle-encryption.json'),'utf8'));
 for(const [key,value]of Object.entries(artifactRecord(config)))if(metadata.artifact?.[key]!==value)throw Error('Private CI bundle provenance mismatch');
 const publicKey=createPublicKey(privateKey).export({type:'spki',format:'pem'});
 if(keyHash(publicKey)!==metadata.keySha256)throw Error('Bundle recipient key mismatch');
 const file=join(directory,'bundle.enc');
 if(metadata.ciphertextBytes!==config.artifact_bytes||(await stat(file)).size!==metadata.ciphertextBytes||
    !/^[a-f0-9]{64}$/.test(metadata.ciphertextSha256)||await digest(file)!==metadata.ciphertextSha256)throw Error('Encrypted bundle integrity mismatch');
 await openFile(file,destination,metadata,privateKey,bundleContext(identity));
 try{await assertArchive(destination,config)}catch(error){await rm(destination,{force:true});throw error}
 return metadata;
}

async function downloadArchive(url,destination,config){
 const response=await fetchArtifact(url);const stated=response.headers.get('content-length');
 if(stated!==null&&Number(stated)!==config.artifact_bytes)throw Error('Private artifact response size mismatch');
 let bytes=0;const file=await openFileHandle(destination,'wx',0o600);
 try{for await(const block of response.body){bytes+=block.length;if(bytes>config.artifact_bytes)throw Error('Private artifact size limit exceeded');let offset=0;while(offset<block.length){const written=await file.write(block,offset,block.length-offset);if(!written.bytesWritten)throw Error('Private artifact write failed');offset+=written.bytesWritten}}}
 finally{await file.close()}
 await assertArchive(destination,config);
}

async function extractArchive(archive,site,configFile){
 await new Promise((yes,no)=>{
  const child=spawn('python3',[join(HERE,'extract_stand_bundle.py'),archive,site,configFile],{stdio:['ignore','ignore','pipe']});
  child.stderr.resume();child.on('error',()=>no(Error('Private app extraction could not start')));
  child.on('close',code=>code===0?yes():no(Error('Private app extraction failed safety or integrity checks')));
 });
}

async function main(){
 const role=process.argv[2],identity=identityFromEnv(),root=resolve(process.env.AUDIT_ROOT),payloadPath=process.env.AUDIT_HANDOFF_PAYLOAD;
 if(!['prepare','unlock'].includes(role)||!payloadPath||!process.env.AUDIT_ROOT)throw Error('Stand transport requires a role and private payload path');
 const configFile=join(HERE,'stand-config.json'),config=JSON.parse(await readFile(configFile,'utf8'));
 const purpose=role==='prepare'?'stand-bundle-prepare':'stand-bundle-unlock';
 if((role==='prepare')!==(identity.caseId==='bundle-prepare'))throw Error('Stand transport case identity mismatch');
 await mkdir(root,{recursive:true,mode:0o700});
 const archive=join(root,'private-ci-app.zip');let payload;
 try{
  payload=validatePayload(purpose,JSON.parse(await readFile(payloadPath,'utf8')));await rm(payloadPath,{force:true});
  if(role==='prepare'){
   await downloadArchive(payload.artifactUrl,archive,config);
   await extractArchive(archive,join(root,'site'),configFile);
   const result=await encryptBundle(archive,join(root,'shared-encrypted-app'),payload.bundleRecipientPublicKeyPem,identity,config);
   console.log('STAND_BUNDLE_READY '+JSON.stringify({runId:identity.runId,runAttempt:identity.runAttempt,...result}));
  }else{
   await decryptBundle(resolve(process.env.STAND_ENCRYPTED_APP),archive,payload.bundlePrivateKeyPem,identity,config);
   await extractArchive(archive,join(root,'site'),configFile);
   console.log('STAND_INSTANCE_ASSETS_VERIFIED '+JSON.stringify({runId:identity.runId,caseId:identity.caseId,sourceCommit:config.source_commit,artifactId:config.artifact_id,assetCount:config.assets.length}));
  }
 }finally{payload=null;await rm(payloadPath,{force:true});await rm(archive,{force:true})}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error(publicFailure());process.exitCode=1});
