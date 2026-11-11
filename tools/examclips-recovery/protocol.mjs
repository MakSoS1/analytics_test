export const REPO='MakSoS1/analytics_test';
export const BRANCH='qa/examclips-audit-2026-11-11';
export const ROSTERS={
 root:[
  {key:'native-rul01',id:'rul01',runId:'43105345959',jobId:130807173816,native:true},
  {key:'rul01',id:'rul01',runId:'43090979122',jobId:130767713526},
  {key:'rul02',id:'rul02',runId:'43091902972',jobId:130770887715},
  {key:'rul06',id:'rul06',runId:'43100076969',jobId:130792293298},
  {key:'enl01',id:'enl01',runId:'43090979122',jobId:130767713525},
  {key:'enl04',id:'enl04',runId:'43098721850',jobId:130784495038}
 ],
 ru:[
  {key:'rul03',id:'rul03',runId:'43098721850',jobId:130784495100},
  {key:'rul04',id:'rul04',runId:'43091902972',jobId:130770887385},
  {key:'rul05',id:'rul05',runId:'43091902972',jobId:130770887544},
  {key:'rul07',id:'rul07',runId:'43098721850',jobId:130784495022},
  {key:'rul08',id:'rul08',runId:'43091902972',jobId:130770887515},
  {key:'rul09',id:'rul09',runId:'43091902972',jobId:130770887513},
  {key:'rul10',id:'rul10',runId:'43091902972',jobId:130770887392}
 ],
 en:[
  {key:'enl02',id:'enl02',runId:'43098721850',jobId:130784495157},
  {key:'enl03',id:'enl03',runId:'43091902972',jobId:130770887526},
  {key:'enl05',id:'enl05',runId:'43091902972',jobId:130770887482},
  {key:'enl06',id:'enl06',runId:'43098721850',jobId:130784495374},
  {key:'enl07',id:'enl07',runId:'43091902972',jobId:130770887543},
  {key:'enl08',id:'enl08',runId:'43091902972',jobId:130770887430},
  {key:'enl09',id:'enl09',runId:'43098721850',jobId:130784495000},
  {key:'enl10',id:'enl10',runId:'43098721850',jobId:130784495042}
 ]
};
export function requireIdentity(env){
 const lane=env.RECOVERY_LANE;
 if(env.GITHUB_REPOSITORY!==REPO||env.GITHUB_REF_NAME!==BRANCH||!Object.hasOwn(ROSTERS,lane))throw Error('UNAUTHORIZED_RECOVERY_IDENTITY');
 for(const k of ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'])if(!/^[1-9]\d*$/.test(env[k]||''))throw Error('INVALID_RECOVERY_RUN');
 return {repository:REPO,branch:BRANCH,runId:env.GITHUB_RUN_ID,runAttempt:env.GITHUB_RUN_ATTEMPT,caseId:lane};
}
export function safeRelative(path){
 if(typeof path!=='string'||!path||path.length>500||path.startsWith('/')||path.includes('\\')||path.includes('\0')||path.split('/').some(x=>!x||x==='.'||x==='..'))throw Error('UNSAFE_RELATIVE_PATH');
 return path;
}
export function targetFor(lane,key){const t=ROSTERS[lane]?.find(x=>x.key===key);if(!t)throw Error('UNSELECTED_CASE');return {...t,runAttempt:'1'};}
export function validateRequest(value,lane,expected){
 if(!value||value.sequence!==expected||!Number.isSafeInteger(expected)||expected<1||expected>10000)throw Error('REQUEST_SEQUENCE_MISMATCH');
 if(!['ingest','files','frame','diagnostics-start','diagnostics-status','inventory','finish'].includes(value.operation))throw Error('UNSUPPORTED_REQUEST');
 if(value.operation!=='finish')targetFor(lane,value.key);
 if(value.operation==='files'){
  if(!Array.isArray(value.paths)||!value.paths.length||value.paths.length>12)throw Error('INVALID_FILE_SELECTION');
  for(const p of value.paths){safeRelative(p);if(!/\.(json|jsonl|txt|srt|png|jpg|jpeg|csv)$/i.test(p))throw Error('FILE_TYPE_NOT_REVIEWABLE');}
 }
 if(value.operation==='frame'){
  safeRelative(value.path);
  if(!/^(?:original-source|clip-\d+)\.mp4$/.test(value.path))throw Error('INVALID_MEDIA_NAME');
  if(!Number.isFinite(value.seconds)||value.seconds<0||value.seconds>10800)throw Error('INVALID_MEDIA_TIME');
 }
 return value;
}
export const canonical=value=>JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))));
