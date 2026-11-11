import {mkdir,readFile,writeFile,readdir,stat,rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sealFile} from './crypto.mjs';
import {identityFromEnv,contextFor} from './audit-context.mjs';
const HERE=dirname(fileURLToPath(import.meta.url));
const config=JSON.parse(await readFile(join(HERE,'run-config.json'),'utf8'));
const output=resolve(process.env.AUDIT_OUT||'audit-evidence');
const artifact=resolve(process.env.AUDIT_ARTIFACT||'audit-encrypted-artifact');
const privateRoot=resolve(process.env.AUDIT_ROOT||'audit-private');
try{await stat(output)}catch{console.log('No audit evidence was created');process.exit(0)}
const key=await readFile(resolve(config.evidence_recipient_pubkey),'utf8');
await mkdir(artifact,{recursive:true,mode:0o700});await mkdir(privateRoot,{recursive:true,mode:0o700});
async function verify(directory) {
  for(const entry of await readdir(directory,{withFileTypes:true})){
    if(entry.isSymbolicLink())throw Error('Evidence cannot contain symbolic links');
    if(/credential|password|cookie|storage.?state|profile|trace|\.har$/i.test(entry.name))throw Error('Authentication material must not be archived');
    const path=join(directory,entry.name);
    if(entry.isDirectory())await verify(path);
    else if(!/\.(json|jsonl|srt|png|mp4|txt)$/i.test(entry.name))throw Error('Unexpected evidence file type');
  }
}
await verify(output);
const zip=join(privateRoot,'evidence.zip');
await new Promise((resolvePromise,reject)=>{
  const script="import pathlib,sys,zipfile\nroot=pathlib.Path(sys.argv[1])\nwith zipfile.ZipFile(sys.argv[2],'w',compression=zipfile.ZIP_STORED,allowZip64=True) as archive:\n for item in sorted(root.rglob('*')):\n  if item.is_file(): archive.write(item,item.relative_to(root))\n";
  const child=spawn('python3',['-c',script,output,zip],{stdio:['ignore','ignore','pipe']});
  child.on('error',reject);child.on('close',code=>code===0?resolvePromise():reject(Error('Evidence ZIP creation failed')));
});
const context=contextFor('evidence',identityFromEnv());
try{
  const metadata=await sealFile(zip,join(artifact,'evidence.enc'),key,context);
  await writeFile(join(artifact,'encryption.json'),JSON.stringify(metadata,null,2)+'\n');
  console.log('ENCRYPTED_EVIDENCE_READY '+JSON.stringify({runId:context.runId,caseId:context.caseId,bytes:(await stat(join(artifact,'evidence.enc'))).size}));
}finally{await rm(zip,{force:true})}
