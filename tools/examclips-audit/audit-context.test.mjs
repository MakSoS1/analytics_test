import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const manifest=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url),'utf8'));
const base={repository:'MakSoS1/analytics_test',branch:'qa/examclips-audit-2026-11-11',runId:'123456',runAttempt:'1',caseId:'en07'};
async function api(){
  const module=await import('./audit-context.mjs').catch(()=>null);
  assert.ok(module,'Case-isolated audit identity must be implemented');
  return module;
}

test('all manifest cases have separate handoff and private paths in one workflow run',async()=>{
  const {handoffLayout,contextFor}=await api();
  const layouts=manifest.cases.map(item=>handoffLayout({...base,caseId:item.id}));
  assert.equal(new Set(layouts.map(item=>item.prefix)).size,manifest.cases.length);
  assert.equal(new Set(layouts.map(item=>item.privateName)).size,manifest.cases.length);
  assert.equal(handoffLayout(base).prefix,'.audit-handoff/123456/en07');
  assert.notEqual(handoffLayout(base).privateName,handoffLayout({...base,runAttempt:'2'}).privateName);
  assert.equal(contextFor('credentials',base).caseId,'en07');
  assert.equal(contextFor('evidence',{...base,caseId:'ru01'}).caseId,'ru01');
});

test('unsafe or incomplete identities cannot publish a credential handoff',async()=>{
  const {handoffLayout,identityFromEnv}=await api();
  assert.throws(()=>handoffLayout({...base,caseId:'../../escape'}),/case/i);
  assert.throws(()=>handoffLayout({...base,caseId:''}),/case/i);
  assert.throws(()=>handoffLayout({...base,repository:'another/repo'}),/authorized/i);
  assert.throws(()=>identityFromEnv({}),/authorized|run|case/i);
});

test('run requests select only known, distinct complete-source cases',async()=>{
  const {selectCaseIds,selectCase}=await api();
  assert.deepEqual(selectCaseIds(manifest,['en07','ru01']),['en07','ru01']);
  assert.equal(selectCase(manifest,'ru01').duration_sec,929);
  assert.throws(()=>selectCaseIds(manifest,[]),/select/i);
  assert.throws(()=>selectCaseIds(manifest,['en07','en07']),/duplicate/i);
  assert.throws(()=>selectCaseIds(manifest,['not-a-source']),/manifest/i);
});

test('the full-source duration determines the bounded 45 or 90 minute budget',async()=>{
  const {caseBudgetSeconds}=await api();
  assert.equal(caseBudgetSeconds({duration_sec:574.309478}),2700);
  assert.equal(caseBudgetSeconds({duration_sec:1800}),2700);
  assert.equal(caseBudgetSeconds({duration_sec:1800.01}),5400);
  assert.equal(caseBudgetSeconds({duration_sec:3806.293}),5400);
  assert.throws(()=>caseBudgetSeconds({duration_sec:0}),/duration/i);
});

test('two-to-three-hour lectures receive five hours for full analysis and exports',async()=>{
 const {caseBudgetSeconds}=await api();
 assert.equal(caseBudgetSeconds({duration_sec:7200}),18000);
 assert.equal(caseBudgetSeconds({duration_sec:10800}),18000);
 assert.equal(caseBudgetSeconds({duration_sec:7199.9}),5400);
 assert.throws(()=>caseBudgetSeconds({duration_sec:10800.1}),/duration/i);
});
