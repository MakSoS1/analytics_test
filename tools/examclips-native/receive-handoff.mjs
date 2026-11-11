import {generateKeyPairSync} from 'node:crypto';
import {mkdir,writeFile,appendFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {algorithm,keyHash} from './crypto.mjs';
import {decodeInput,MAX_ENVELOPE_BYTES} from './input.mjs';
import {identityFromEnv,handoffLayout,contextFor,safeError} from './native-context.mjs';

async function main(){
  const identity=identityFromEnv(),{repository,branch,runId,runAttempt,caseId}=identity;
  const token=process.env.GITHUB_TOKEN;
  if(!token||!process.env.RUNNER_TEMP||!process.env.GITHUB_OUTPUT)throw Error('ACTIONS_RUNTIME_REQUIRED');
  const {prefix,privateName}=handoffLayout(identity),directory=join(process.env.RUNNER_TEMP,privateName);
  await mkdir(directory,{recursive:true,mode:0o700});
  const privatePath=join(directory,'handoff-private.pem'),credentialPath=join(directory,'credentials.json'),inputPath=join(directory,'input.json');
  const context=contextFor('native-input',identity);
  async function api(path,method='GET',body){
    const response=await fetch('https://api.github.com/repos/'+repository+'/contents/'+path+(method==='GET'?'?ref='+encodeURIComponent(branch):''),{
      method,headers:{Accept:'application/vnd.github+json',Authorization:'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28',...(body?{'Content-Type':'application/json'}:{})},
      body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(30000)});
    if(response.status===404&&method==='GET')return null;
    if(!response.ok){const error=Error('HANDOFF_HTTP_'+response.status);error.status=response.status;throw error}
    return response.json();
  }
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:4096,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  await writeFile(privatePath,privateKey,{mode:0o600});
  const descriptor={version:1,algorithm,context,publicKeyPem:publicKey,keySha256:keyHash(publicKey),
    createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+14*60*1000).toISOString(),payload:'gzip-json-native-input-v1'};
  try{
    for(let attempt=0;attempt<8;attempt++){
      const previous=await api(prefix+'/public.json');
      try{
        await api(prefix+'/public.json','PUT',{message:'Publish ephemeral native export handoff key for run '+runId+' case '+caseId,branch,
          content:Buffer.from(JSON.stringify(descriptor,null,2)+'\n').toString('base64'),...(previous?{sha:previous.sha}:{})});break;
      }catch(error){if(error.status!==409||attempt===7)throw error;await delay(Math.min(15000,1000*2**attempt)+Math.floor(Math.random()*1000))}
    }
    console.log('NATIVE_HANDOFF_READY '+JSON.stringify({runId,runAttempt,caseId,path:prefix+'/public.json',keySha256:descriptor.keySha256,expiresAt:descriptor.expiresAt}));
    let accepted=false;
    while(Date.now()<Date.parse(descriptor.expiresAt)){
      const file=await api(prefix+'/encrypted.json');
      if(file){
        if(file.size>MAX_ENVELOPE_BYTES||file.encoding!=='base64'||typeof file.content!=='string')throw Error('INVALID_HANDOFF_CONTAINER');
        let envelope;try{envelope=JSON.parse(Buffer.from(file.content,'base64'))}catch{throw Error('INVALID_HANDOFF_JSON')}
        if(envelope.keySha256!==descriptor.keySha256||envelope.context?.runAttempt!==runAttempt){await delay(15000);continue}
        const payload=decodeInput(envelope,privateKey,context),{credentials,...projectInput}=payload;
        await writeFile(credentialPath,JSON.stringify(credentials),{mode:0o600,flag:'wx'});
        await writeFile(inputPath,JSON.stringify(projectInput),{mode:0o600,flag:'wx'});
        await appendFile(process.env.GITHUB_OUTPUT,'credentials_path='+credentialPath+'\ninput_path='+inputPath+'\nprivate_dir='+directory+'\n');
        accepted=true;console.log('NATIVE_HANDOFF_ACCEPTED '+JSON.stringify({runId,runAttempt,caseId,primaryRun:payload.origin.runId}));break;
      }
      await delay(15000);
    }
    if(!accepted)throw Error('NATIVE_HANDOFF_TIMEOUT');
  }finally{await rm(privatePath,{force:true})}
}
main().catch(error=>{console.error(safeError(error));process.exitCode=1});
