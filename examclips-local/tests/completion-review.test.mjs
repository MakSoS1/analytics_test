import test from 'node:test';import assert from 'node:assert/strict';
import {buildReviewPayload,reviewHasEvidence,normalizeReview,prepareReviewRequest,reviewPrompt} from '../src/completion-review.js';
const chunks=[
 {start:10,end:25,text:'Сначала разберём, что такое Docker контейнер.'},
 {start:25,end:55,text:'Контейнер использует образ и изолирует зависимости приложения.'},
 {start:60,end:90,text:'Поэтому можно запустить приложение независимо от среды системы.'},
 {start:92,end:115,text:'Теперь рассмотрим создание собственного образа Docker.'}
];
test('review context includes exact prior and following phrases, without arbitrary video',()=>{
 const p=buildReviewPayload({start:25,end:90,title:'Docker'},chunks,150,{margin:40});
 assert.equal(p.before.length,1);assert.equal(p.inside.length,2);assert.equal(p.after.length,1);
 assert.ok(!JSON.stringify(p).includes('videoData'));
});
test('model can never certify fake evidence or hallucinated quote',()=>{
 const p=buildReviewPayload({start:10,end:90},chunks,150);
 const verdict=normalizeReview({verdict:'complete',confidence:.99,evidence:['The lecturer made an imaginary claim'],explanation:'yes'},p);
 assert.equal(verdict.verdict,'uncertain');assert.equal(verdict.confidence,0);
});
test('literal evidence accepted but verdict still explicitly advisory',()=>{
 const p=buildReviewPayload({start:10,end:90},chunks,150);
 const x=normalizeReview({verdict:'complete',confidence:.81,
  evidence:['Сначала разберём, что такое Docker контейнер.'],
  explanation:'Тема раскрывается; проверить вручную',suggestedEndDelta:350},p);
 assert.equal(x.evidenceVerified,true);assert.equal(x.suggestedEndDelta,0);
 assert.match(x.disclaimer,/проверить/);
});
test('border suggestion is clamped at 45 seconds and failed model output coerces uncertainty',()=>{
 const p=buildReviewPayload({start:10,end:90},chunks,150);
 const r=normalizeReview({verdict:'definitely-correct',confidence:999,
   evidence:['Сначала разберём, что такое Docker контейнер.'],suggestedStartDelta:-25},p);
 assert.equal(r.verdict,'uncertain');assert.equal(r.confidence,1);assert.equal(r.suggestedStartDelta,-25);
});
test('missing transcript and oversized prompt rejected before local request',()=>{
 assert.throws(()=>prepareReviewRequest({inside:[],before:[],after:[]}));
 assert.throws(()=>prepareReviewRequest({inside:[{text:'x'.repeat(16000)}]}));
});
test('model prompt contains only transcript evidence and schema instruction',()=>{
 const p=buildReviewPayload({start:10,end:90},chunks,150);
 const str=reviewPrompt(p);
 assert.match(str,/suggestedStartDelta/);assert.match(str,/Сначала разберём/);
 assert.match(str,/uncertain/);
});
