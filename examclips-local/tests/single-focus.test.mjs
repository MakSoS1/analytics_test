import test from 'node:test';import assert from 'node:assert/strict';
import {editorialGeometry,paletteFor,titleCardOpacity} from '../src/editorial-motion.js';
test('content uses the former header area and does not collide with captions or teacher',()=>{
 const g=editorialGeometry();assert.ok(g.stage.y<60);assert.ok(g.stage.w>=680);
 assert.ok(g.stage.y+g.stage.h<=g.subtitles.y);assert.ok(g.subtitles.y+g.subtitles.h<=g.speaker.y);
});
test('title is an opening card only, default palette is restrained dark',()=>{
 assert.equal(titleCardOpacity(0),1);assert.equal(titleCardOpacity(2),0);
 assert.equal(titleCardOpacity(50),0);assert.equal(paletteFor().background,'#191C22');
});

import {makeStoryboard} from '../src/scene-model.js';
test('a prose panel is framed around its text, not the adjacent diagram or slide border',()=>{
 const width=160,height=90,pixels=new Uint8ClampedArray(width*height*4).fill(255);
 for(let y=18;y<74;y++)for(const x of [82,150]){const k=(y*width+x)*4;pixels[k]=pixels[k+1]=pixels[k+2]=0;}
 const lines=[{text:'A useful topic',confidence:95,box:{x0:100,y0:22,x1:133,y1:28}},
 {text:'The system shares the underlying resources directly.',confidence:95,box:{x0:100,y0:30,x1:146,y1:38}}];
 const scene=makeStoryboard({width,height,pixels,lines,duration:30});
 const prose=scene.panels.find(p=>p.text.includes('shares'));
 assert.ok(prose.rect.x>.55);assert.ok(prose.rect.h<.4);
});
