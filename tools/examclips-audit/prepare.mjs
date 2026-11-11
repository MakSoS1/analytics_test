import {readFile,appendFile} from 'node:fs/promises';
import {selectCaseIds,selectCase,caseBudgetSeconds} from './audit-context.mjs';

const manifest=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url),'utf8'));
const request=JSON.parse(await readFile(new URL('./run-request.json',import.meta.url),'utf8'));
const ids=selectCaseIds(manifest,request.case_ids);
for(const id of ids)caseBudgetSeconds(selectCase(manifest,id));
if(process.env.GITHUB_OUTPUT)await appendFile(process.env.GITHUB_OUTPUT,'case_ids='+JSON.stringify(ids)+'\n');
console.log('MATRIX_READY '+JSON.stringify({requestId:request.request_id||null,count:ids.length,caseIds:ids}));
