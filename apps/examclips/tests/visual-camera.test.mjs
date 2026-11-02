import test from 'node:test';
import assert from 'node:assert/strict';
import {contentBlocks,changeRegion,frameContent,cameraAt,createCameraIndexer,detectWebcam,
  assertCameraTrack,withAspect,STAGE} from '../src/visual-camera.js';
import {editorialGeometry,cameraStageAspect} from '../src/editorial-motion.js';
import {safeProjectSnapshot} from '../src/project-library.js';

const W=320,H=180;
function frame(paint){
 const rgba=new Uint8ClampedArray(W*H*4).fill(250);
 const fill=(x,y,w,h,c)=>{for(let j=Math.round(y*H);j<Math.round((y+h)*H);j++)for(let i=Math.round(x*W);i<Math.round((x+w)*W);i++){
  const k=(j*W+i)*4;rgba[k]=c[0];rgba[k+1]=c[1];rgba[k+2]=c[2];rgba[k+3]=255}};
 // Text-like rows: short dark dashes on a line.
 const text=(x,y,w,rows)=>{for(let r=0;r<rows;r++)for(let i=0;i<w;i+=.02)fill(x+i,y+r*.045,.012,.02,[30,30,40])};
 // Thin decorative curve across the slide, like a template ornament.
 const curve=()=>{
  let last=null;
  for(let i=0;i<W;i++){
   const j=Math.round(H*.55+Math.sin(i/30)*H*.3);
   for(let y=Math.min(j,last??j);y<=Math.max(j,last??j);y++){const k=(y*W+i)*4;rgba[k]=150;rgba[k+1]=80;rgba[k+2]=230}
   last=j;
  }
 };
 paint({fill,text,curve});
 return rgba;
}
const twoColumn=(bullets=3)=>frame(({fill,text,curve})=>{
 text(.05,.04,.5,1);                       // heading
 fill(.05,.3,.38,.45,[120,160,210]);       // diagram on the left
 text(.6,.3,.3,bullets);                   // bullet list on the right
 curve();
});
test('content blocks keep columns apart and ignore heading and ornaments',()=>{
 const blocks=contentBlocks(twoColumn(),W,H);
 assert.equal(blocks.length,2,JSON.stringify(blocks));
 const [left,right]=blocks;
 assert.ok(left.x<.1&&left.x+left.w<.5,'diagram first in reading order');
 assert.ok(right.x>.55&&right.y>.25,'bullets block below heading band');
 assert.ok(right.h<.25,'thin template curve does not stretch the bullet block');
});
test('a revealed bullet is a small local change, not a slide change',()=>{
 const change=changeRegion(twoColumn(3),twoColumn(4),W,H);
 assert.ok(change.fraction>0&&change.fraction<.05);
 assert.ok(change.box.x>=.55&&change.box.y>=.4);
});
test('framing fills a vertical stage and zooms a narrow list for reading',()=>{
 const f=frameContent({x:.6,y:.3,w:.25,h:.15},{sourceWidth:1600,sourceHeight:900});
 assert.ok(f.zoom>1.25&&f.zoom<=1.45,'list is magnified but not cropped tight, got '+f.zoom);
 const aspect=f.rect.w*1600/(f.rect.h*900);
 assert.ok(Math.abs(aspect-STAGE.w/STAGE.h)<.01,'crop matches the stage, no letterbox');
 assert.ok(f.rect.y<=.3&&f.rect.y+f.rect.h>=.45,'content stays inside the crop');
});
test('a block wider than any vertical crop is panned instead of shrunk',()=>{
 const f=frameContent({x:.02,y:.2,w:.95,h:.3},{sourceWidth:1600,sourceHeight:900});
 assert.ok(f.pan,'pan target exists');
 assert.ok(f.rect.x<.05&&f.pan.x+f.pan.w>.95);
 assert.ok(f.zoom>=.8);
});
test('camera interpolates between keys and holds afterwards',()=>{
 const a={x:0,y:0,w:.4,h:.8},b={x:.5,y:.1,w:.2,h:.4};
 const track={version:2,source:{width:1600,height:900},keys:[{start:0,end:0,rect:a},{start:10,end:11,rect:b}]};
 assert.deepEqual(cameraAt(track,5),a);
 assert.deepEqual(cameraAt(track,12),b);
 const mid=cameraAt(track,10.5);
 assert.ok(mid.w<a.w&&mid.w>b.w);
 assert.ok(assertCameraTrack(track));
 assert.equal(cameraAt(null,3),null);
});
test('indexer cuts on a new slide and moves to the revealed bullet',()=>{
 const ix=createCameraIndexer({width:W,height:H,sourceWidth:1600,sourceHeight:900});
 const blank=frame(({text})=>text(.05,.04,.5,1));
 for(let t=0;t<4;t++)ix.push(t,blank);
 for(let t=4;t<20;t++)ix.push(t,twoColumn(2));
 for(let t=20;t<40;t++)ix.push(t,twoColumn(3));
 const track=ix.finish(40);
 assert.ok(assertCameraTrack(track));
 assert.ok(track.keys.every((k,i)=>i===0||k.start>=track.keys[i-1].start),'keys ordered');
 const late=cameraAt(track,30);
 assert.ok(late.x>.45,'camera is on the bullet list after the reveal: '+JSON.stringify(late));
});
test('webcam tile is found from persistent local motion',()=>{
 const base=()=>twoColumn();
 const pairs=[];
 for(let i=0;i<8;i++){
  const a=base(),b=base();
  for(let y=Math.round(H*.82);y<H;y++)for(let x=Math.round(W*.8);x<W;x++){
   const k=(y*W+x)*4;
   a[k]=a[k+1]=a[k+2]=60;
   b[k]=b[k+1]=b[k+2]=60;
   // A moving face inside the tile.
   if(Math.hypot(x-W*.9-i%3,y-H*.91)<9){b[k]=200;b[k+1]=150;b[k+2]=120}
  }
  pairs.push([a,b]);
 }
 const found=detectWebcam(pairs,W,H);
 assert.ok(found,'webcam found');
 assert.ok(found.box.x>.75&&found.box.y>.78,JSON.stringify(found.box));
 assert.ok(found.box.w<.25&&found.box.h<.25);
});
test('stage aspect can change without leaving the source',()=>{
 const r=withAspect({x:.6,y:.2,w:.3,h:.6},.63,1600,900);
 assert.ok(Math.abs(r.w*1600/(r.h*900)-.63)<.01);
 assert.ok(r.x>=0&&r.y>=0&&r.x+r.w<=1.0001&&r.y+r.h<=1.0001);
});
test('presenter strip shows the whole webcam tile at content width',()=>{
 const g=editorialGeometry(720,1280,{speaker:true,compact:true});
 assert.equal(g.stage.w,684);assert.equal(g.speaker.w,g.stage.w);
 assert.ok(g.stage.h>=600,'slide stage stays tall');
 const wide=editorialGeometry(720,1280,{speaker:true,compact:true,speakerAspect:240/137});
 assert.ok(Math.abs(wide.speaker.w/wide.speaker.h-240/137)<.03,'webcam proportions are kept, nothing is cut off');
 assert.ok(Math.abs(cameraStageAspect(240/137)-wide.stage.w/wide.stage.h)<1e-9);
 assert.ok(g.subtitles.y>=g.stage.y+g.stage.h&&g.speaker.y>=g.subtitles.y+g.subtitles.h);
});
test('project snapshot keeps a valid camera and drops a malformed one',()=>{
 const camera={version:2,source:{width:1600,height:900},speaker:{x:.84,y:.84,w:.15,h:.15},
  keys:[{start:0,end:0,rect:{x:0,y:0,w:.4,h:.8}}],ranges:[{start:0,end:60}]};
 const base={clips:[],chunks:[],duration:60};
 assert.deepEqual(safeProjectSnapshot({...base,lectureCamera:camera}).lectureCamera,camera);
 assert.equal(safeProjectSnapshot({...base,lectureCamera:{version:2,keys:[{rect:{x:2}}]}}).lectureCamera,null);
});

test('the shot avoids the slide webcam tile and never shows a sliver of the heading',()=>{
 const avoid={x:.83,y:.82,w:.17,h:.18};
 // Bullet list in a card whose lower right corner holds the webcam tile.
 const f=frameContent({x:.6,y:.22,w:.3,h:.2},{sourceWidth:1600,sourceHeight:900,aspect:.99,avoid});
 const r=f.rect,hits=r.x+r.w>avoid.x+1e-6&&r.y+r.h>avoid.y+1e-6;
 assert.ok(!hits,'webcam tile is outside the shot: '+JSON.stringify(r));
 assert.ok(r.x<=.6-.01&&r.x+r.w>=.9,'the whole list stays visible');
 assert.ok(r.y>=.159,'shot starts below the heading band');
});
test('old camera tracks are recomputed with current framing rules',()=>{
 assert.equal(assertCameraTrack({version:1,source:{width:1600,height:900},keys:[]}),false);
});
