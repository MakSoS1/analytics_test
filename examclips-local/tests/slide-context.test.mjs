import test from 'node:test';import assert from 'node:assert/strict';
import {analyzeSlideContext,speechTarget,sourceEvidence,selectedTabFromPixels} from '../src/slide-context.js';
const mk=(text,x0,y0,x1,y1,confidence=95)=>({text,box:{x0,y0,x1,y1},confidence});
const lines=[
 mk('Explore how each method works',58,22,530,60),
 mk('Detailed guide',58,101,320,130),
 mk('Overview',91,163,206,187),
 mk('EPDE',266,163,335,187),
 mk('PySINDy',392,163,515,187),
 mk('A method description',90,280,455,319)
];
const sample=(x,y)=> x<235&&y>140&&y<207?[220,233,252]:[250,251,253];
test('selects active tab from measured blue background without relying on text guessing',()=>{
 const ctx=analyzeSlideContext(lines,650,450,{sampleRgb:sample});
 assert.equal(ctx.kind,'software-ui');
 assert.equal(ctx.activeTab,'Overview');
 assert.equal(ctx.tabs.length,3);
});
test('language mention redirects focus to correct inactive tab',()=>{
 const ctx=analyzeSlideContext(lines,650,450,{sampleRgb:sample});
 const target=speechTarget(ctx,'Теперь поговорим про PySINDy, используем его');
 assert.equal(target.type,'tab');assert.equal(target.text,'PySINDy');
});
test('ambiguous pixels do not invent an active tab',()=>{
 const ctx=analyzeSlideContext(lines,650,450);
 assert.equal(ctx.activeTab,null);
 assert.equal(ctx.tabs.length,3);
});
test('speaker overlay is excluded and branding does not become lecture title',()=>{
 const ctx=analyzeSlideContext([mk('Containers vs. Virtual Machines',70,30,740,91),
   mk('ITMO',1340,35,1420,77),mk('camera subtitles',1300,800,1570,835)],1600,900,
 {speaker:{x:.78,y:.78,w:.21,h:.2}});
 assert.equal(ctx.title,'Containers vs. Virtual Machines');
 assert.deepEqual(ctx.brandText,['ITMO']);
 assert.ok(!ctx.recognizedText.join(' ').includes('camera subtitles'));
});
test('formulas/code are flagged instead of automatically re-typeset',()=>{
 const ctx=analyzeSlideContext([
  mk('Docker Networking',60,30,430,90),
  mk('FROM python:3.11',100,180,490,230),
  mk('x² + 2x = 0',100,270,410,310)],1600,900);
 assert.equal(ctx.elements[0].kind,'code');
 assert.equal(ctx.elements[1].kind,'formula');
 assert.equal(ctx.originalPixelRequired,true);
});
test('invalid geometry and confidence filtered deterministically',()=>{
 const list=sourceEvidence([mk('invalid',-15,40,100,90),mk('low score',10,20,40,35,8),mk('good',10,20,80,45)],650,450);
 assert.equal(list.length,1);assert.equal(list[0].text,'good');
});
