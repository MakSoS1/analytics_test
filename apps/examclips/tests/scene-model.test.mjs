import test from 'node:test';import assert from 'node:assert/strict';
import {flattenOcr,layoutFromOcr,makeStoryboard,focusForSpeech,sceneAt,sourceRect,assertScene} from '../src/scene-model.js';
const lines=[
 {text:'Docker Networking',box:{x0:50,y0:30,x1:600,y1:100},confidence:94},
 {text:'Container images architecture',box:{x0:100,y0:200,x1:500,y1:240},confidence:94},
 {text:'Docker networks bridge overlay',box:{x0:1000,y0:250,x1:1530,y1:300},confidence:90}
];
test('Tesseract block structure extracts words and bounds',()=>{
 const data=flattenOcr([{paragraphs:[{lines:[{bbox:{x0:10,y0:20,x1:100,y1:50},words:[{text:'Docker',confidence:90},{text:'bridge',confidence:80}]}]}]}]);
 assert.equal(data[0].text,'Docker bridge');assert.equal(data[0].confidence,85)
});
test('layout returns source-faithful panels; never fabricates rewritten diagrams',()=>{
 const result=layoutFromOcr(lines,1600,900);
 assert.equal(result.title,'Docker Networking');assert.equal(result.panels.length,2);
 assert.match(result.panels[0].text,/Container/);assert.match(result.panels[1].text,/bridge/);
 assert.ok(result.panels[0].rect.w<.8);
});
test('director matches OCR and spoken lecture context',()=>{
 const a=[{text:'container virtualization'},{text:'docker networks bridge overlay'}];
 assert.equal(focusForSpeech(a,'Now we discuss docker networks',0),1);
 assert.equal(focusForSpeech(a,'Unmatched explanation',0),0);
});
test('storyboard is time indexed and original crop geometry is valid',()=>{
 const s=makeStoryboard({width:1600,height:900,lines,duration:40,chunks:[{start:0,end:7,text:'container images'},{start:10,end:18,text:'docker networks bridge'}]});
 assert.equal(s.version,2);assert.ok(assertScene(s));assert.ok(s.beats.length>=4);
 assert.equal(sceneAt(s,1).focus,0);assert.equal(sceneAt(s,12).focus,1);
 const r=sourceRect(s.panels[1].rect,1600,900);assert.ok(r.w>250);
});
test('non-OCR fallback retains source clips',()=>{
 const s=makeStoryboard({width:640,height:360,duration:4});
 assert.equal(s.method,'pixel-preserving-split');assert.equal(s.panels.length,1);assert.ok(assertScene(s))
});
test('malformed scene and out-of-bounds coordinates are rejected',()=>{
 const s=makeStoryboard({width:640,height:360,duration:4});s.speaker.x=1.2;assert.equal(assertScene(s),false)
});
