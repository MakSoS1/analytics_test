import test from 'node:test';import assert from 'node:assert/strict';
import {detectMotionROI} from '../src/speaker-motion.js';
function image(){const x=new Uint8ClampedArray(320*180*4);x.fill(248);return x}
test('select moving webcam on lower right',()=>{
 const a=image(),b=image(),c=image();
 for(let y=150;y<177;y++)for(let x=260;x<315;x++){const p=(y*320+x)*4;b[p]=30;c[p]=175}
 const out=detectMotionROI([a,b,c],320,180);assert.equal(out.found,true);
 assert.equal(out.candidate,'bottom-right');assert.ok(out.confidence>.04)
});
test('static image uses disclosed fallback',()=>{
 const x=image();const result=detectMotionROI([x,x],320,180);
 assert.equal(result.found,false);assert.equal(result.confidence,0)
});
test('do not mistake other corner for lower right',()=>{
 const a=image(),b=image();
 for(let y=150;y<178;y++)for(let x=5;x<65;x++){const p=(y*320+x)*4;b[p]=20}
 assert.equal(detectMotionROI([a,b],320,180).candidate,'bottom-left')
});
