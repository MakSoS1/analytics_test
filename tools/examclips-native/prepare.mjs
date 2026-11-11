import {readFile,appendFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {safeError} from './native-context.mjs';
export function selectRequest(request){
  if(request?.version!==1)throw Error('INVALID_NATIVE_REQUEST_VERSION');
  if(typeof request.enabled!=='boolean')throw Error('INVALID_ENABLE_FLAG');
  if(!request.enabled)return {enabled:false,caseIds:[]};
  const ids=request.case_ids;
  if(!Array.isArray(ids)||ids.length<1||ids.length>2||new Set(ids).size!==ids.length||ids.some(id=>typeof id!=='string'||!/^(?:ru|en)l(?:0[1-9]|10)$/.test(id)))throw Error('SELECT_ONE_OR_TWO_DISTINCT_LONG_CASES');
  return {enabled:true,caseIds:[...ids]};
}
async function main(){
  const selected=selectRequest(JSON.parse(await readFile(new URL('./run-request.json',import.meta.url),'utf8')));
  if(process.env.GITHUB_OUTPUT)await appendFile(process.env.GITHUB_OUTPUT,'enabled='+selected.enabled+'\ncase_ids='+JSON.stringify(selected.caseIds)+'\n');
  console.log('NATIVE_MATRIX_SELECTION '+JSON.stringify({...selected,auditKind:'native_export_probe',corpusCountIncrement:0}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{console.error(safeError(error));process.exitCode=1});
