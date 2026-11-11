import {clipSpec} from './input.mjs';

function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  return value;
}
const equal=(a,b)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));
export function verifyRestoredProject(original,current,clipId){
  if(!current||!Array.isArray(current.clips)||!Array.isArray(current.chunks))throw Error('RESTORED_PROJECT_INVALID');
  for(const name of ['name','size','modified'])if(current.source?.[name]!==original.source?.[name])throw Error('RESTORED_SOURCE_CHANGED');
  if(current.duration!==original.duration||!equal(current.chunks,original.chunks))throw Error('RESTORED_TRANSCRIPT_CHANGED');
  if((current.settings?.outputQuality||'standard')!==(original.settings?.outputQuality||'standard'))throw Error('RESTORED_QUALITY_CHANGED');
  const before=original.clips.filter(c=>String(c.id)===clipId),after=current.clips.filter(c=>String(c.id)===clipId);
  if(before.length!==1||after.length!==1||!equal(clipSpec(before[0]),clipSpec(after[0])))throw Error('RESTORED_CLIP_CHANGED');
  const clip=after[0],segments=Array.isArray(clip.segments)&&clip.segments.length?clip.segments:[{start:clip.start,end:clip.end}];
  return {clip,clipIndex:current.clips.findIndex(c=>String(c.id)===clipId),segments,outputSeconds:segments.reduce((n,s)=>n+s.end-s.start,0)};
}
export function classifyNativeStatus(text){
  if(/Распознавание:\s*\d+\s*\/\s*\d+\s*с/.test(text))return 'unexpected_asr';
  if(/^Ошибка:|^Остановлено:|^Экспорт остановлен|^Экспорт прерван/.test(text))return 'failed';
  if(/^Экспорт завершён:/.test(text)||/большой MP4 будет собираться в RAM/.test(text))return 'wrong_ram_path';
  if(/^Большой MP4 сохранён напрямую на диск\./.test(text))return 'native_complete';
  return 'processing';
}
export function expectedFrames(segments,fps){
  if(![15,30].includes(fps))throw Error('UNEXPECTED_EXPORT_FPS');
  return segments.reduce((n,p)=>n+Math.max(1,Math.ceil((p.end-p.start-1e-4)*fps)),0);
}
