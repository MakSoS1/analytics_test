import {mkdir,readFile,writeFile,readdir,stat,rm,appendFile} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {resolve,join,dirname,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sealFile} from './crypto.mjs';
import {identityFromEnv,contextFor} from './audit-context.mjs';

const HERE=dirname(fileURLToPath(import.meta.url));
const excluded=new Set(['scene-frame-scores.jsonl','scene-metadata.log']);

export async function packageReview({evidence,artifact,privateRoot,publicKey,context}){
 evidence=resolve(evidence);artifact=resolve(artifact);privateRoot=resolve(privateRoot);
 const files=[];
 async function visit(directory){
  for(const entry of await readdir(directory,{withFileTypes:true})){
   if(entry.isSymbolicLink())throw Error('Review evidence cannot contain symbolic links');
   if(/credential|password|cookie|storage.?state|profile|trace|\.har$/i.test(entry.name))throw Error('Authentication material must not be archived');
   const path=join(directory,entry.name);
   if(entry.isDirectory()){await visit(path);continue;}
   if(/\.mp4$/i.test(entry.name)||excluded.has(entry.name))continue;
   if(!/\.(json|jsonl|srt|png|jpg|jpeg|txt|log|ffscript)$/i.test(entry.name))throw Error('Unexpected review evidence file type');
   files.push({path:relative(evidence,path),bytes:(await stat(path)).size});
  }
 }
 await visit(evidence);
 if(!files.length)return {available:false};
 await mkdir(privateRoot,{recursive:true,mode:0o700});
 const review=join(artifact,'review');await mkdir(review,{recursive:true,mode:0o700});
 const list=join(privateRoot,'review-file-list.json'),zip=join(privateRoot,'review.zip'),ciphertext=join(review,'review.enc');
 const manifest={version:1,scope:'Metadata, projects, transcripts, sampled frames and decode logs; no media files',
  excluded:['all MP4 files','full per-frame scene JSONL','raw per-frame scene metadata log'],files};
 await writeFile(list,JSON.stringify(manifest),{mode:0o600});
 try{
  await new Promise((resolvePromise,reject)=>{
   const script="import json,pathlib,sys,zipfile\nroot=pathlib.Path(sys.argv[1]);meta=json.loads(pathlib.Path(sys.argv[2]).read_text())\nwith zipfile.ZipFile(sys.argv[3],'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as archive:\n archive.writestr('review-package-manifest.json',json.dumps(meta,ensure_ascii=False,indent=2))\n for item in meta['files']: archive.write(root/item['path'],item['path'])\n";
   const child=spawn('python3',['-c',script,evidence,list,zip],{stdio:['ignore','ignore','pipe']});
   child.on('error',reject);child.on('close',code=>code===0?resolvePromise():reject(Error('Compact review ZIP creation failed')));
  });
  const meta=await sealFile(zip,ciphertext,publicKey,context);
  const hash=createHash('sha256');for await(const block of createReadStream(ciphertext))hash.update(block);
  meta.ciphertextSha256=hash.digest('hex');meta.ciphertextBytes=(await stat(ciphertext)).size;
  await writeFile(join(review,'review-encryption.json'),JSON.stringify(meta,null,2)+'\n',{mode:0o600});
  return {available:true,files:files.length,bytes:meta.ciphertextBytes,sha256:meta.ciphertextSha256};
 }catch(error){await rm(ciphertext,{force:true});throw error}
 finally{await rm(zip,{force:true});await rm(list,{force:true})}
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const config=JSON.parse(await readFile(join(HERE,'run-config.json'),'utf8'));
 const evidence=resolve(process.env.AUDIT_OUT||'audit-evidence');
 try{await stat(evidence)}catch{console.log('No review evidence was created');process.exit(0)}
 const result=await packageReview({evidence,artifact:process.env.AUDIT_ARTIFACT||'audit-encrypted-artifact',
  privateRoot:process.env.AUDIT_ROOT||'audit-private',publicKey:await readFile(resolve(config.evidence_recipient_pubkey),'utf8'),
  context:{...contextFor('evidence',identityFromEnv()),artifactKind:'compact-review'}});
 if(process.env.GITHUB_OUTPUT)await appendFile(process.env.GITHUB_OUTPUT,'available='+result.available+'\n');
 console.log('ENCRYPTED_REVIEW_READY '+JSON.stringify(result));
}
