const REPOSITORY='MakSoS1/analytics_test';
const BRANCH='qa/examclips-audit-2026-11-11';
const safeCase=id=>typeof id==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id);

function identity(value){
  const {repository,branch,runId,runAttempt,caseId}=value;
  if(repository!==REPOSITORY||branch!==BRANCH)throw Error('Audit identity requires the authorized repository and isolated branch');
  if(!/^\d+$/.test(runId||'')||!/^\d+$/.test(runAttempt||''))throw Error('A numeric Actions run and attempt are required');
  if(!safeCase(caseId))throw Error('A safe, nonempty matrix case ID is required');
  return {repository,branch,runId:String(runId),runAttempt:String(runAttempt),caseId};
}

export function identityFromEnv(env=process.env){
  return identity({repository:env.GITHUB_REPOSITORY,branch:env.GITHUB_REF_NAME,runId:env.GITHUB_RUN_ID,
    runAttempt:env.GITHUB_RUN_ATTEMPT,caseId:env.AUDIT_CASE_ID});
}
export function handoffLayout(value){
  const {runId,runAttempt,caseId}=identity(value);
  return {prefix:'.audit-handoff/'+runId+'/'+caseId,privateName:'examclips-private-'+runId+'-'+runAttempt+'-'+caseId};
}
export function contextFor(purpose,value){
  if(!['credentials','evidence'].includes(purpose))throw Error('Unsupported audit encryption purpose');
  return {purpose,...identity(value)};
}
export function selectCaseIds(manifest,requested){
  if(!Array.isArray(manifest?.cases))throw Error('A source manifest is required');
  const known=manifest.cases.map(item=>item.id);
  if(known.some(id=>!safeCase(id))||new Set(known).size!==known.length)throw Error('Source manifest contains unsafe or duplicate case IDs');
  if(!Array.isArray(requested)||!requested.length||requested.length>25)throw Error('Select one to 25 source cases');
  if(new Set(requested).size!==requested.length)throw Error('Duplicate requested case ID');
  for(const id of requested)if(!safeCase(id)||!known.includes(id))throw Error('Selected case is absent from manifest: '+id);
  return [...requested];
}
export function selectCase(manifest,caseId){
  selectCaseIds(manifest,[caseId]);
  return manifest.cases.find(item=>item.id===caseId);
}
export function caseBudgetSeconds(item){
  const duration=Number(item.duration_sec);
  if(!Number.isFinite(duration)||duration<=0||duration>10800)throw Error('Source duration must be positive and at most three hours');
  return duration>=7200?18000:duration>1800?5400:2700;
}
