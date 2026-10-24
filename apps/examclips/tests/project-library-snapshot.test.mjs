import test from 'node:test';
import assert from 'node:assert/strict';
import {safeProjectSnapshot} from '../src/project-library.js';

const defaults={language:'auto',asrModel:'tiny',asrLimit:'all',ocrEngine:'auto',outputQuality:'standard'};
const legacy=()=>({
 schema:1,duration:300,
 clips:[{id:'saved-topic',title:'Сохранённая правка',status:'approved',
  start:20,end:170,segments:[{start:140,end:170},{start:20,end:45}],
  screenplay:{summary:[{text:'Точный тезис',evidence:[{start:22,end:25,quote:'Реплика преподавателя',source:'lecture'}]}]}}],
 chunks:[{start:20,end:45,text:'Сохранённая расшифровка'}],
 sceneCuts:[0,100],lectureChapters:[{start:0,end:300,title:'Сохранённая глава'}],
 selected:0,activeTab:'clip',view:{zoom:12,offset:.62}
});

test('legacy snapshots retain existing data and receive safe UI and setting defaults',()=>{
 const original=legacy(),snapshot=safeProjectSnapshot(original);
 assert.equal(snapshot.schema,2);
 for(const key of ['duration','clips','chunks','sceneCuts','lectureChapters','selected','activeTab','view'])
  assert.deepEqual(snapshot[key],original[key],key);
 assert.deepEqual(snapshot.settings,defaults);
 assert.deepEqual(snapshot.ui,{detailOpen:false,catalogScroll:0});
 assert.equal(original.settings,undefined);
 assert.equal(original.ui,undefined);
});

test('extended snapshots round-trip allowed settings and navigation without sharing edited objects',()=>{
 const original={...legacy(),settings:{language:'ru',asrModel:'base',asrLimit:'900',
  ocrEngine:'rapid',outputQuality:'high'},ui:{detailOpen:true,catalogScroll:1420.5}};
 const snapshot=safeProjectSnapshot(original);
 assert.deepEqual(snapshot.settings,original.settings);
 assert.deepEqual(snapshot.ui,original.ui);
 const loaded=safeProjectSnapshot(JSON.parse(JSON.stringify(snapshot)));
 assert.deepEqual(loaded,snapshot);
 snapshot.clips[0].segments[0].start=145;
 snapshot.clips[0].title='Другая правка';
 snapshot.settings.language='en';
 snapshot.ui.catalogScroll=0;
 assert.equal(original.clips[0].segments[0].start,140);
 assert.equal(original.clips[0].title,'Сохранённая правка');
 assert.equal(original.settings.language,'ru');
 assert.equal(original.ui.catalogScroll,1420.5);
});

test('optional snapshot fields whitelist exact UI values and discard unknown properties',()=>{
 const snapshot=safeProjectSnapshot({...legacy(),
  settings:{language:'fr',asrModel:'remote',asrLimit:300,ocrEngine:'cloud',outputQuality:'4k',apiKey:'discard'},
  ui:{detailOpen:'true',catalogScroll:'500',remoteUrl:'discard'}});
 assert.deepEqual(snapshot.settings,defaults);
 assert.deepEqual(snapshot.ui,{detailOpen:false,catalogScroll:0});
 assert.deepEqual(safeProjectSnapshot({...legacy(),settings:null,ui:[]}).settings,defaults);
 assert.deepEqual(safeProjectSnapshot({...legacy(),settings:{language:'en',asrLimit:'300',ocrEngine:'tesseract'}}).settings,
  {...defaults,language:'en',asrLimit:'300',ocrEngine:'tesseract'});
});

test('snapshot catalog scroll is finite and bounded',()=>{
 for(const [given,expected] of [[-500,0],[Infinity,0],[NaN,0],[1e12,1e7],[325.25,325.25]]){
  const snapshot=safeProjectSnapshot({...legacy(),ui:{detailOpen:true,catalogScroll:given}});
  assert.deepEqual(snapshot.ui,{detailOpen:true,catalogScroll:expected});
 }
});

test('extending optional fields keeps legacy validation and defaults intact',()=>{
 assert.throws(()=>safeProjectSnapshot({duration:100,clips:[],settings:defaults}));
 assert.throws(()=>safeProjectSnapshot({duration:0,clips:[],chunks:[]}));
 assert.throws(()=>safeProjectSnapshot({duration:10801,clips:[],chunks:[]}));
 const snapshot=safeProjectSnapshot({duration:100,clips:[],chunks:[]});
 assert.deepEqual(snapshot.sceneCuts,[]);
 assert.deepEqual(snapshot.lectureChapters,[]);
 assert.equal(snapshot.selected,0);
 assert.equal(snapshot.activeTab,'timeline');
 assert.deepEqual(snapshot.view,{zoom:1,offset:0});
});
