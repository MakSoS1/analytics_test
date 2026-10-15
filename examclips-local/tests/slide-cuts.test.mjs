import test from 'node:test';import assert from 'node:assert/strict';
import {slideDifference,detectSceneCuts} from '../src/slide-cuts.js';
function frame(color){const v=new Uint8ClampedArray(160*90*4);for(let i=0;i<v.length;i+=4){v[i]=color;v[i+1]=color;v[i+2]=color;v[i+3]=255}return v}
test('stable slide with camera motion at bottom does not split',()=>{
 const a=frame(255),b=frame(255);
 for(let y=76;y<90;y++)for(let x=130;x<160;x++){const i=(y*160+x)*4;b[i]=50}
 assert.ok(slideDifference(a,b)<.01);
 assert.deepEqual(detectSceneCuts([{time:0,rgba:a,width:160,height:90},{time:12,rgba:b,width:160,height:90}]),[0]);
});
test('slide transition yields chapter at later timestamp',()=>{
 const a=frame(255),b=frame(255);
 for(let y=18;y<66;y++)for(let x=12;x<115;x++){const i=(y*160+x)*4;b[i]=0;b[i+1]=35;b[i+2]=55}
 assert.ok(slideDifference(a,b)>.15);
 const cuts=detectSceneCuts([{time:0,rgba:a,width:160,height:90},{time:8,rgba:a,width:160,height:90},
 {time:24,rgba:b,width:160,height:90},{time:32,rgba:b,width:160,height:90}]);
 assert.deepEqual(cuts,[0,24]);
});
test('duplicate slides do not produce multiple chapters',()=>{const a=frame(0);assert.deepEqual(detectSceneCuts([{time:0,rgba:a,width:160,height:90},{time:20,rgba:a,width:160,height:90}]),[0])});
