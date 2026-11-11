import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {ROSTERS,targetFor,validateRequest,requireIdentity,assertArtifactPins} from './protocol.mjs';
assert.equal(process.env.RECOVERY_PROFILE,'native-rul01-r4');
assert.deepEqual(Object.keys(ROSTERS),['root']);
assert.equal(ROSTERS.root.length,1);
const target=targetFor('root','native-rul01');
assert.equal(target.runId,'43116421328');assert.equal(target.jobId,130845540911);assert.equal(target.native,true);
assert.throws(()=>targetFor('root','rul01'),/UNSELECTED_CASE/);
assert.throws(()=>targetFor('en','enl01'),/UNSELECTED_CASE/);
assert.throws(()=>requireIdentity({GITHUB_REPOSITORY:'MakSoS1/analytics_test',GITHUB_REF_NAME:'qa/examclips-audit-2026-11-11',GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',RECOVERY_LANE:'ru'}),/UNAUTHORIZED_RECOVERY_IDENTITY/);
const request={sequence:1,operation:'frame',key:'native-rul01',path:'native-clip.mp4',seconds:.1};
assert.equal(validateRequest(request,'root',1),request);
for(const path of ['../native-clip.mp4','sub/native-clip.mp4','/native-clip.mp4','native-clip.mp4/else','native-other.mp4'])
 assert.throws(()=>validateRequest({...request,path},'root',1));
const artifact={id:13898898668,size_in_bytes:148916917,digest:'sha256:4e20c0a2e1db2b36636b51c8aca84ade52b35caf857c4efdef86c77d4e01f5a5'};
assertArtifactPins(target,[artifact]);
for(const invalid of [[],[artifact,artifact],[{...artifact,id:1}],[{...artifact,size_in_bytes:1}],[{...artifact,digest:'sha256:'+'0'.repeat(64)}]])
 assert.throws(()=>assertArtifactPins(target,invalid),/PINNED_NATIVE_ARTIFACT_MISMATCH/);
const primary=spawnSync(process.execPath,['--input-type=module','-e',`
 import assert from 'node:assert/strict';
 import {ROSTERS,validateRequest,targetFor} from './protocol.mjs';
 assert.equal(Object.values(ROSTERS).flat().filter(t=>!t.native).length,20);
 assert.equal(targetFor('root','native-rul01').runId,'43105345959');
 for(const key of ['rul01','native-rul01'])assert.throws(()=>validateRequest({sequence:1,operation:'frame',key,path:'native-clip.mp4',seconds:0},'root',1),/INVALID_MEDIA_NAME/);
`],{cwd:process.cwd(),env:{...process.env,RECOVERY_PROFILE:'primary'},encoding:'utf8'});
assert.equal(primary.status,0,primary.stderr);
console.log(JSON.stringify({nativeProfile:'passed',runId:target.runId,jobId:target.jobId,artifactId:artifact.id,primaryCasesUnchanged:20,supplementaryCases:1}));
