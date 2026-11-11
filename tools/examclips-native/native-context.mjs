export const REPOSITORY='MakSoS1/analytics_test';
export const BRANCH='qa/examclips-audit-2026-11-11';
export function nativeIdentity(value){
  const {repository,branch,runId,runAttempt,caseId}=value||{};
  if(repository!==REPOSITORY||branch!==BRANCH)throw Error('UNAUTHORIZED_REPOSITORY_OR_BRANCH');
  if(!/^[1-9]\d*$/.test(String(runId||''))||!/^[1-9]\d*$/.test(String(runAttempt||'')))throw Error('INVALID_RUN_IDENTITY');
  if(typeof caseId!=='string'||!/^(?:ru|en)l(?:0[1-9]|10)$/.test(caseId))throw Error('INVALID_SOURCE_CASE');
  return {repository,branch,runId:String(runId),runAttempt:String(runAttempt),caseId};
}
export function identityFromEnv(env=process.env){
  return nativeIdentity({repository:env.GITHUB_REPOSITORY,branch:env.GITHUB_REF_NAME,runId:env.GITHUB_RUN_ID,runAttempt:env.GITHUB_RUN_ATTEMPT,caseId:env.AUDIT_CASE_ID});
}
export function contextFor(purpose,value){
  if(!['native-input','evidence'].includes(purpose))throw Error('INVALID_ENCRYPTION_PURPOSE');
  return {purpose,...nativeIdentity(value)};
}
export function handoffLayout(value){
  const {runId,runAttempt,caseId}=nativeIdentity(value);
  return {prefix:'.audit-native-handoff/'+runId+'/'+caseId,privateName:'examclips-native-private-'+runId+'-'+runAttempt+'-'+caseId};
}
export const safeError=error=>/^[A-Z][A-Z0-9_]{2,100}$/.test(error?.message||'')?error.message:'NATIVE_OPERATION_FAILED';
