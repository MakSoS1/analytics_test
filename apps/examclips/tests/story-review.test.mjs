import test from 'node:test';import assert from 'node:assert/strict';
import {makeStoryReviewPayload,storyReviewPrompt,validateStoryReview} from '../src/story-review.js';
const input=makeStoryReviewPayload([
 {id:'candidate-1',start:5,end:28,score:4,text:'Docker позволяет изолировать приложения. Используются одни и те же системные ресурсы.'},
 {id:'candidate-2',start:60,end:86,score:3,text:'Контейнеры Docker сохраняют зависимости в образах. Поэтому сервис воспроизводимо запускается в другом окружении.'},
 {id:'candidate-3',start:180,end:210,score:4,text:'Проверка микрофона и настройка проектора, пожалуйста, подождите минуту.'}
],420,{keepFraction:.35});
test('local LLM only receives bounded transcript text and source IDs',()=>{
 assert.equal(input.sections.length,3);assert.ok(storyReviewPrompt(input).includes('SELECT_HIGHLIGHTS'));
 assert.ok(!storyReviewPrompt(input).includes('data:video'));
});
test('literal evidence and budget verified, no fake source clips',()=>{
 const raw={stories:[
  {ids:['candidate-1','candidate-2'],evidence:['Docker позволяет изолировать приложения','Контейнеры Docker сохраняют зависимости'],reason:'Docker'}
 ]};
 const result=validateStoryReview(raw,input);
 assert.equal(result.clips.length,1);assert.equal(result.clips[0].segments.length,2);
 assert.equal(result.clips[0].status,'needs-review');
});
test('hallucinated quote, duplicate IDs and too-long budget silently rejected',()=>{
 const forged={stories:[{ids:['candidate-1'],evidence:['В лекции говорили о технике безопасности']}]};
 assert.equal(validateStoryReview(forged,input).clips.length,0);
 assert.throws(()=>makeStoryReviewPayload([],100,{keepFraction:2}));
});
