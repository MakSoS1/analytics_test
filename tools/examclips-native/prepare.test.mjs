import test from 'node:test';
import assert from 'node:assert/strict';
let prepare={};try{prepare=await import('./prepare.mjs')}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error}
test('disabled preparation cannot accidentally select a live matrix',()=>{
  assert.equal(typeof prepare.selectRequest,'function');
  assert.deepEqual(prepare.selectRequest({version:1,enabled:false,case_ids:[]}),{enabled:false,caseIds:[]});
  assert.throws(()=>prepare.selectRequest({version:1,enabled:'true',case_ids:['rul01']}),/INVALID_ENABLE_FLAG/);
});
test('a reviewed native request selects only one or two distinct corpus cases',()=>{
  assert.equal(typeof prepare.selectRequest,'function');
  assert.deepEqual(prepare.selectRequest({version:1,enabled:true,case_ids:['rul01','enl04']}),{enabled:true,caseIds:['rul01','enl04']});
  for(const ids of [[],['rul01','rul01'],['rul01','enl01','enl04'],['../rul01']])assert.throws(()=>prepare.selectRequest({version:1,enabled:true,case_ids:ids}));
});
