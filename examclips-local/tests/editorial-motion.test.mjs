import test from 'node:test';import assert from 'node:assert/strict';
import {easeOutCubic,editorialTimeline,editorialGeometry,captionCueAt,measureWrapped,fitTypography,suitableOcrLines,paletteFor} from '../src/editorial-motion.js';
const ctx={font:'',measureText(text){const size=Number(this.font.match(/\d+px/)?.[0].replace('px',''))||24;return {width:Array.from(text).length*size*.59}}};
test('easing clamps and animates without jumping',()=>{
 assert.equal(easeOutCubic(-1),0);assert.equal(easeOutCubic(2),1);assert.ok(easeOutCubic(.25)>0&&easeOutCubic(.25)<1)
});
test('chapter focus has short eased crossfade only when target changes',()=>{
 const scene={beats:[{time:0,focus:0},{time:9,focus:1},{time:18,focus:1}]};
 assert.deepEqual(editorialTimeline(scene,5).current,0);
 const mid=editorialTimeline(scene,9.2);assert.ok(mid.mix>0&&mid.mix<1);assert.equal(mid.previous,0);
 assert.equal(editorialTimeline(scene,10).mix,1);
 assert.equal(editorialTimeline(scene,18).mix,1);
});
test('geometry respects video dimensions, margin and no presenter variant',()=>{
 for(const dims of [[720,1280],[1080,1920]]){
  const g=editorialGeometry(...dims);for(const r of [g.title,g.stage,g.speaker,g.subtitles]){
   assert.ok(r.x>=0&&r.y>=0&&r.w>0&&r.h>0&&r.x+r.w<=dims[0]+.1&&r.y+r.h<=dims[1]+.1)
  }
 }
 assert.equal(editorialGeometry(720,1280,{speaker:false}).speaker,null);
});
test('all OCR strings are measured and fitted without overflow',()=>{
 const data='The automatic docker networking subsystem explains local bridges and virtual interfaces';
 const t=fitTypography(ctx,data,{width:380,height:205,maxFont:45,minFont:24,maxLines:5});
 assert.ok(t.lines.length>=1);assert.ok(t.lines.length*t.lineHeight<=205);
 for(const line of t.lines)assert.ok(ctx.measureText(line).width<=380);
 const long=measureWrapped(ctx,'supercalifragilisticexpialidocious',70);
 assert.ok(long.lines.length>1);
});
test('captions are paged to a manageable visual phrase without rewriting transcript',()=>{
 const c=[{start:10,end:20,text:'one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty'}];
 assert.equal(captionCueAt(c,11),'one two three four five six seven eight nine ten');
 assert.equal(captionCueAt(c,19),'eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty');
 assert.equal(captionCueAt(c,21),'');
});
test('OCR text is not reflowed if unsuitable or source-only',()=>{
 assert.deepEqual(suitableOcrLines({lines:['valid teaching sentence','bad {formula}','     ','A']},''),[]);
 assert.equal(suitableOcrLines({},'').length,0);
 assert.equal(paletteFor('no-such-theme').background,'#F5F4F0');
});
