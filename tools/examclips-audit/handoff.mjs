import {generateKeyPairSync} from 'node:crypto';
import {mkdir,readFile,writeFile,appendFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {algorithm,keyHash,open} from './crypto.mjs';
import {identityFromEnv,handoffLayout,contextFor} from './audit-context.mjs';

const identity=identityFromEnv();
const {repository,branch,runId,runAttempt,caseId}=identity;
const {prefix,privateName}=handoffLayout(identity);
const token=process.env.GITHUB_TOKEN;
if(!token||!process.env.RUNNER_TEMP)throw Error('Actions runtime is required');
const directory=join(process.env.RUNNER_TEMP,privateName);
await mkdir(directory,{mode:0o700,recursive:true});
const privatePath=join(directory,'handoff-private.pem'),credentialPath=join(directory,'credentials.json');
const context=contextFor('credentials',identity);
async function api(path,method='GET',body) {
  const response=await fetch('https://api.github.com/repos/'+repository+'/contents/'+path+(method==='GET'?'?ref='+encodeURIComponent(branch):''),{
    method,headers:{Accept:'application/vnd.github+json',Authorization:'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28',
      ...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(30000)});
  if(response.status===404&&method==='GET')return null;
  if(!response.ok){const error=Error('GitHub handoff request failed with HTTP '+response.status);error.status=response.status;throw error;}
  return response.json();
}
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:4096,
  publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
await writeFile(privatePath,privateKey,{mode:0o600});
const descriptor={version:1,algorithm,context,publicKeyPem:publicKey,keySha256:keyHash(publicKey),
  createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+14*60*1000).toISOString()};
try {
  for(let attempt=0;attempt<8;attempt++){
    const existing=await api(prefix+'/public.json');
    try{
      await api(prefix+'/public.json','PUT',{message:'Publish ephemeral audit handoff public key for run '+runId+' case '+caseId,branch,
        content:Buffer.from(JSON.stringify(descriptor,null,2)+'\n').toString('base64'),...(existing?{sha:existing.sha}:{})});
      break;
    }catch(error){if(error.status!==409||attempt===7)throw error;await delay(Math.min(15000,1000*2**attempt)+Math.floor(Math.random()*1500));}
  }
  await writeFile(join(directory,'public.json'),JSON.stringify(descriptor,null,2));
  console.log('HANDOFF_READY '+JSON.stringify({runId,runAttempt,caseId,path:prefix+'/public.json',keySha256:descriptor.keySha256,expiresAt:descriptor.expiresAt}));
  let received=false;
  while(Date.now()<Date.parse(descriptor.expiresAt)) {
    const file=await api(prefix+'/encrypted.json');
    if(file) {
      if(file.size>65536)throw Error('Encrypted credential envelope is too large');
      const envelope=JSON.parse(Buffer.from(file.content,'base64').toString('utf8'));
      // An old attempt remains public but cannot be used by this fresh private key.
      if(envelope.keySha256!==descriptor.keySha256||envelope.context?.runAttempt!==runAttempt) {await delay(15000);continue;}
      const plain=open(envelope,privateKey,context);
      const credentials=JSON.parse(plain.toString('utf8'));
      if(typeof credentials.email!=='string'||!/^\S+@\S+\.\S+$/.test(credentials.email)||credentials.email.length>254||
        typeof credentials.password!=='string'||credentials.password.length<8||credentials.password.length>1024||
        /[\r\n]/.test(credentials.password))throw Error('Invalid credential payload');
      for(const value of [credentials.email,credentials.password])console.log('::add-mask::'+value.replaceAll('%','%25'));
      await writeFile(credentialPath,JSON.stringify(credentials),{mode:0o600});plain.fill(0);
      await appendFile(process.env.GITHUB_OUTPUT,'credentials_path='+credentialPath+'\nprivate_dir='+directory+'\n');
      received=true;console.log('HANDOFF_ACCEPTED '+JSON.stringify({runId,runAttempt,caseId}));break;
    }
    await delay(15000);
  }
  if(!received)throw Error('Encrypted credential handoff timed out');
} finally {await rm(privatePath,{force:true});}
