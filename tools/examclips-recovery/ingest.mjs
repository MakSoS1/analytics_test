import {mkdir,readFile,writeFile,rm,statfs,stat} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {openFile,keyHash} from '../examclips-audit/crypto.mjs';
import {REPO,BRANCH,canonical} from './protocol.mjs';
const HERE=dirname(fileURLToPath(import.meta.url)),execute=promisify(execFile);
async function hash(path){const h=createHash('sha256');for await(const chunk of createReadStream(path))h.update(chunk);return h.digest('hex');}
async function python(args){return (await execute('python3',args,{timeout:900000,maxBuffer:16*1024**2})).stdout;}
export async function ingestCase({target,root,privateKey,gh,downloadArtifact}){
 const job=await gh('/repos/'+REPO+'/actions/jobs/'+target.jobId);
 if(job.run_id!==Number(target.runId)||job.status!=='completed')throw Error('ORIGINAL_JOB_NOT_TERMINAL');
 const uploadSteps=job.steps.filter(s=>/^Upload encrypted .*part /.test(s.name)&&s.conclusion==='success');
 const expectedPrefix='examclips-long-encrypted-'+target.runId+'-1-'+target.id+'-part-';
 let artifacts=[];
 for(let page=1;page<=5;page++){
  const data=await gh('/repos/'+REPO+'/actions/runs/'+target.runId+'/artifacts?per_page=100&page='+page);
  artifacts.push(...data.artifacts.filter(a=>a.name.startsWith(expectedPrefix)));
  if(page*100>=data.total_count)break;
 }
 artifacts.sort((a,b)=>a.name.localeCompare(b.name));
 if(!artifacts.length||artifacts.length>20||uploadSteps.length!==artifacts.length)throw Error('INCOMPLETE_ARTIFACT_SET');
 artifacts.forEach((a,i)=>{if(a.name!==expectedPrefix+String(i+1).padStart(4,'0')||a.expired||!/^sha256:[0-9a-f]{64}$/.test(a.digest||''))throw Error('INVALID_ARTIFACT_METADATA');});
 const total=artifacts.reduce((n,a)=>n+a.size_in_bytes,0);
 await mkdir(root,{recursive:true,mode:0o700});
 const fs=await statfs(root);if(fs.bavail*fs.bsize<total*2.1+2*1024**3)throw Error('INSUFFICIENT_RECOVERY_DISK');
 const transport=join(root,'transport'),parts=join(transport,'parts'),evidence=join(root,'evidence');
 await mkdir(parts,{recursive:true,mode:0o700});
 const receipts=[];
 for(let i=0;i<artifacts.length;i++){
  const a=artifacts[i],zip=join(transport,'part.zip'),part=join(parts,'part-'+String(i+1).padStart(4,'0'));
  await downloadArtifact(a.id,zip);
  const actual=await hash(zip);if(actual!==a.digest.slice(7)||(await stat(zip)).size!==a.size_in_bytes)throw Error('ARTIFACT_ZIP_INTEGRITY_FAILED');
  await python([join(HERE,'zip_guard.py'),'outer',zip,part]);await rm(zip);
  receipts.push({id:a.id,name:a.name,bytes:a.size_in_bytes,sha256:actual,expiresAt:a.expires_at});
 }
 const ciphertext=join(transport,'evidence.enc'),plainZip=join(transport,'evidence.zip');
 await python([resolve(HERE,'../examclips-audit/split_evidence.py'),'join',parts,ciphertext]);
 const metadata=JSON.parse(await readFile(join(parts,'part-0001/encryption.json'),'utf8'));
 const expected={purpose:'evidence',repository:REPO,branch:BRANCH,runId:target.runId,runAttempt:'1',caseId:target.id};
 if(canonical(metadata.context||{})!==canonical(expected))throw Error('ORIGINAL_CONTEXT_MISMATCH');
 const expectedPublic=await readFile(resolve(HERE,'../examclips-audit/evidence-recipient.pub.pem'),'utf8');
 if(metadata.keySha256!==keyHash(expectedPublic))throw Error('RECIPIENT_FINGERPRINT_MISMATCH');
 await rm(parts,{recursive:true});
 await openFile(ciphertext,plainZip,metadata,privateKey,expected);await rm(ciphertext);
 const inventory=JSON.parse(await python([join(HERE,'zip_guard.py'),'inner',plainZip,evidence,target.id]));
 await rm(plainZip);await rm(transport,{recursive:true});
 const run=JSON.parse(await readFile(join(evidence,'run.json'),'utf8'));
 const result=JSON.parse(await readFile(join(evidence,target.id,'result.json'),'utf8'));
 if(!target.native){const manifest=JSON.parse(await readFile(join(evidence,'selected-manifest.json'),'utf8'));if(!Array.isArray(manifest.cases)||manifest.cases.length!==1||manifest.cases[0]?.id!==target.id)throw Error('SELECTED_MANIFEST_MISMATCH');}
 if(result.id!==target.id)throw Error('RESULT_CASE_MISMATCH');
 for(const [k,v]of Object.entries({repository:REPO,runId:target.runId,runAttempt:'1',caseId:target.id})){
  if(run[k]!==undefined&&String(run[k])!==v)throw Error('RUN_RECORD_MISMATCH');
 }
 const original=inventory.find(x=>x.path===target.id+'/original-source.mp4');
 if(!target.native&&(!original||!result.source?.sha256||original.sha256!==result.source.sha256))throw Error('ORIGINAL_SOURCE_HASH_MISMATCH');
 const receipt={schema:1,target,authenticated:true,context:expected,originalJob:{id:job.id,status:job.status,conclusion:job.conclusion,completedAt:job.completed_at},artifacts:receipts,inventory,source:result.source??null,qualityVerdict:null,createdAt:new Date().toISOString()};
 await writeFile(join(root,'receipt.json'),JSON.stringify(receipt,null,2),{mode:0o600});
 return {root,evidence,caseDir:join(evidence,target.id),receipt};
}
