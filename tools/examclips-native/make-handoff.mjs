import {readFile,lstat,writeFile} from 'node:fs/promises';
import {buildInput,encodeInput} from './input.mjs';
import {safeError} from './native-context.mjs';

async function main(){
  const [descriptorFile,requestFile,outputFile]=process.argv.slice(2);
  if(!descriptorFile||!requestFile||!outputFile)throw Error('THREE_INPUT_PATHS_REQUIRED');
  const st=await lstat(requestFile);
  if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)||st.size>65536)throw Error('REQUEST_FILE_MUST_BE_PRIVATE');
  let request,descriptor;
  try{request=JSON.parse(await readFile(requestFile,'utf8'));descriptor=JSON.parse(await readFile(descriptorFile,'utf8'))}catch{throw Error('INVALID_PRIVATE_REQUEST_OR_DESCRIPTOR')}
  const payload=await buildInput(request.receipt_path,request.project_path,request.selected_clip_id,request.source_url,request.credentials_file,request.state_path);
  const envelope=encodeInput(payload,descriptor);
  await writeFile(outputFile,JSON.stringify(envelope,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log('NATIVE_INPUT_ENCRYPTED '+JSON.stringify({runId:descriptor.context.runId,runAttempt:descriptor.context.runAttempt,
    caseId:descriptor.context.caseId,primaryRun:payload.origin.runId,projectSha256:payload.origin.projectSha256}));
}
main().catch(error=>{console.error(safeError(error));process.exitCode=1});
