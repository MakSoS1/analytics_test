import test from 'node:test';
import assert from 'node:assert/strict';
let state={};try{state=await import('./native-state.mjs')}catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error}
const project={schema:2,duration:7350,source:{name:'rul01.mp4',size:1024,modified:1794420000123},chunks:[{start:0,end:1,text:'fixture'}],
  settings:{outputQuality:'standard'},clips:[{id:'one',title:'Original title',start:1,end:400,segments:[{start:1,end:151},{start:200,end:375}],layout:'hybrid'}]};

test('restored project must retain the selected title, EDL and source identity',()=>{
  assert.equal(typeof state.verifyRestoredProject,'function');
  assert.equal(state.verifyRestoredProject(project,structuredClone(project),'one').outputSeconds,325);
  const changed=structuredClone(project);changed.clips[0].segments[1].end=376;
  assert.throws(()=>state.verifyRestoredProject(project,changed,'one'),/RESTORED_CLIP_CHANGED/);
  const renamed=structuredClone(project);renamed.clips[0].title='Different title';
  assert.throws(()=>state.verifyRestoredProject(project,renamed,'one'),/RESTORED_CLIP_CHANGED/);
  const wrongSource=structuredClone(project);wrongSource.source.modified++;
  assert.throws(()=>state.verifyRestoredProject(project,wrongSource,'one'),/RESTORED_SOURCE_CHANGED/);
});

test('RAM success and stopped/error statuses cannot masquerade as native-stream completion',()=>{
  assert.equal(typeof state.classifyNativeStatus,'function');
  assert.equal(state.classifyNativeStatus('Большой MP4 сохранён напрямую на диск. Откройте файл в карточке кнопкой «Открыть готовый MP4».'),'native_complete');
  assert.equal(state.classifyNativeStatus('Видео 90/9000 кадров · фрагмент 1/20'),'processing');
  assert.equal(state.classifyNativeStatus('Экспорт завершён: 20.0 МБ'),'wrong_ram_path');
  assert.equal(state.classifyNativeStatus('Ошибка: decoder failed'),'failed');
  assert.equal(state.classifyNativeStatus('Экспорт остановлен'),'failed');
  assert.equal(state.classifyNativeStatus('Распознавание: 30 / 7350 с'),'unexpected_asr');
});

test('frame accounting matches retained per-segment frame ceilings',()=>{
  assert.equal(typeof state.expectedFrames,'function');
  assert.equal(state.expectedFrames([{start:0,end:1.01},{start:10,end:11}],15),31);
  assert.equal(state.expectedFrames([{start:0,end:1},{start:10,end:11}],30),60);
});
