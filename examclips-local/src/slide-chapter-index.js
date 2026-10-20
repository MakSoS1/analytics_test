/**
 * Best-effort OCR of ORIGINAL slide headings, to add structural chapter cues.
 * Cost bounded by frame samples + OCR budget, not video frame count.
 * The audio transcript, not slide headings, establishes whether a concept
 * is actually explained and can be used in a microvideo.
 */
import {sampleSlideCuts} from './slide-cuts.js';
import {recognizeEducationalFrame} from './scene-analysis.js';
import {normalizeSlideChapters} from './lecture-outline.js';
const ignore=/^(?:itmo|i?тмо|slide\s*\d+|\d+|www\.|http)/iu;
const intro=/(?:about\s+me|lecture\s+\d+\s+brief|course\s+(?:agenda|outline)|welcome|обо\s+мне|план\s+лекц)/iu;
const normalize=text=>String(text||'').toLowerCase()
  .replace(/[^\p{L}\p{N}]+/gu,' ').trim().replace(/\s+/gu,' ');
const similar=(a,b)=>{
 if(!a||!b)return false;
 if(a===b||a.includes(b)||b.includes(a))return true;
 const set=x=>new Set(x.split(' ').filter(Boolean));
 const aa=set(a),bb=set(b);let common=0;
 for(const x of aa)if(bb.has(x))common++;
 return common>=2&&common/Math.max(aa.size,bb.size)>.65;
};
export function slideHeadingFromLines(lines=[],width=1152,height=220){
 const candidates=lines.filter(l=>{
   const b=l.box;return b&&Number(l.confidence)>=38&&
    b.x0<width*.75&&b.y0<height*.79&&b.y1>0&&
    (b.x1-b.x0)>width*.05&&!ignore.test(String(l.text||''))&&
    /[\p{L}]{3,}/u.test(l.text||'');
 }).sort((a,b)=>a.box.y0-b.box.y0);
 const heading=candidates[0];
 const near=candidates.filter(l=>l===heading||(l.box.y0-heading.box.y1<Math.max(8,(heading.box.y1-heading.box.y0)*.55)&&
   l.box.y1-l.box.y0>=(heading.box.y1-heading.box.y0)*.7));
 const text=near.slice(0,2).map(x=>String(x.text||'').trim())
  .filter(x=>x.length>=6).join(' ').slice(0,92);
 return text;
}
export function chaptersFromHeadings(headings,duration){
 const sorted=(headings||[]).filter(x=>x.title&&Number.isFinite(x.start))
  .sort((a,b)=>a.start-b.start);
 const markers=[];
 for(const mark of sorted){
   const key=normalize(mark.title);
   const previous=markers.at(-1);
   if(previous&&similar(previous.normalized,key))continue;
   markers.push({start:mark.start,title:mark.title,normalized:key,
     key:intro.test(mark.title)?'introduction':'slide-heading',
     source:'slide-ocr',confidence:'review-required'});
 }
 return normalizeSlideChapters(markers.map((item,i)=>({
   start:item.start,end:markers[i+1]?.start??duration,title:item.title,
   key:item.key,source:item.source,confidence:item.confidence
 })),duration);
}
export async function indexLectureSlides(media,{signal,language='en',
  maxOcrFrames=70,onProgress=()=>{},recognize=recognizeEducationalFrame}={}){
 if(!media?.videoSink||!Number.isFinite(media.duration))throw Error('No video samples');
 const cuts=await sampleSlideCuts(media,{start:0,end:media.duration},{
   sampleEvery:Math.max(12,Math.min(28,Math.round(media.duration/150))),
   signal,onProgress});
 const indices=[...new Set([0,...cuts])].filter(t=>t>=0&&t<media.duration-1);
 const stride=Math.max(1,Math.ceil(indices.length/maxOcrFrames));
 const sampled=indices.filter((_,i)=>i===0||i%stride===0||i===indices.length-1);
 const headings=[];let errors=0;
 const canvas=document.createElement('canvas');
 canvas.width=1152;canvas.height=220;
 const ctx=canvas.getContext('2d',{willReadFrequently:true});
 const fullCanvas=document.createElement('canvas');
 fullCanvas.width=1152;fullCanvas.height=Math.max(1,Math.round(1152*media.height/media.width));
 const fullCtx=fullCanvas.getContext('2d');
 for(let i=0;i<sampled.length;i++){
   if(signal?.aborted)throw new DOMException('Stopped','AbortError');
   let sample;
   try{
     sample=await media.videoSink.getSample(Math.min(media.duration-.1,sampled[i]+1.0));
     if(!sample)continue;
     ctx.clearRect(0,0,canvas.width,canvas.height);
     // Header crop suppresses most presenter tiles and irrelevant body text.
     sample.draw(fullCtx,0,0,fullCanvas.width,fullCanvas.height);
     ctx.drawImage(fullCanvas,0,0,fullCanvas.width,fullCanvas.height*.28,0,0,1152,220);
     const found=await recognize(canvas,{language,signal,
       onProgress:()=>{}});
     const title=slideHeadingFromLines(found.lines,canvas.width,canvas.height);
     if(title)headings.push({start:sampled[i],title});
   }catch(error){
     if(error.name==='AbortError')throw error;
     errors++;
     if(errors>=4){
       onProgress('OCR слайдов недоступен, использую транскрипт.');
       break;
     }
   }finally{sample?.close()}
   if(i%4===0||i===sampled.length-1)
     onProgress('Поиск глав по слайдам: '+(i+1)+'/'+sampled.length);
 }
 return {chapters:chaptersFromHeadings(headings,media.duration),cuts,
   inspected:sampled.length,recognized:headings.length,ocrErrors:errors};
}
