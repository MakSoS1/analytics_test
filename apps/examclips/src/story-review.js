/** Optional same-device Ollama semantic selection, grounded in literal source excerpts. */
import {titleFromText} from './segments.js';
import {summarizeStoryPlan} from './selective-stories.js';
const upper=Math.max;
export function makeStoryReviewPayload(candidates,duration,{keepFraction=.30}={}){
 if(!(duration>0&&keepFraction>0&&keepFraction<=1))throw Error('Invalid review settings');
 const selected=(candidates||[]).filter(c=>c&&Number.isFinite(c.start)&&Number.isFinite(c.end)&&c.end>c.start&&c.end<=duration);
 // Include both high-scoring moments and representative points through time.
 // Each candidate has only speech TEXT; never video, PCM, frames or tokens.
 const ranked=[...selected].sort((a,b)=>b.score-a.score||a.start-b.start).slice(0,40);
 const payload={duration,keepFraction,sections:ranked.map(c=>({
   id:String(c.id).slice(0,36),start:c.start,end:c.end,
   text:String(c.text||'').slice(0,520)
 }))};
 if(JSON.stringify(payload).length>28000)throw Error('Too many candidate texts for local model');
 return payload;
}
export function storyReviewPrompt(payload){
 return [
  'SELECT_HIGHLIGHTS. You are a conservative educational SHORT-FORM EDITOR, not a copywriter.',
  'You receive only candidate transcript excerpts from a lecture, with exact IDs and source timestamps.',
  'Choose only portions that teach a concrete useful insight, explanation, demonstration, result or surprising fact.',
  'Ignore greetings, pauses, technical setup, repetitive/organizational chatter, incomplete statements and disconnected claims.',
  'Group IDs from distant times ONLY if they clearly form the SAME independently understandable microtopic with topic -> explanation -> result.',
  'Do NOT try to include all lecture content. A large unused portion is desirable. Budget is only a ceiling.',
  'Never invent new speech, quotations, sources or topics; return exactly JSON object:',
  '{"stories":[{"ids":["candidate-1","candidate-9"],"evidence":["literal excerpt from first chosen candidate","literal excerpt from second chosen candidate"],"reason":"brief Russian explanation"}]}',
  'Maximum 8 stories; 1-3 excerpts per story. Do not repeat any source ID. List IDs in intended PLAYBACK order.',
  'Every evidence entry must be 10+ consecutive characters COPIED VERBATIM from the associated source candidate text.',
  'If no truly useful coherent explanation is present return {"stories":[]} rather than inventing an interesting one.',
  'Source transcript may have ASR errors. Choose conservatively and do not treat confidence as proof.',
  'DATA:',JSON.stringify(payload)
 ].join('\n').slice(0,30000);
}
export function validateStoryReview(raw,payload){
 if(!raw||!Array.isArray(raw.stories))throw Error('Local selection response has invalid schema');
 const byId=new Map(payload.sections.map(c=>[c.id,c]));
 const seen=new Set(),stories=[];let cumulative=0;
 const budget=payload.duration*payload.keepFraction;
 for(const entry of raw.stories.slice(0,8)){
   if(!entry||!Array.isArray(entry.ids)||!Array.isArray(entry.evidence))continue;
   if(entry.ids.length<1||entry.ids.length>3||entry.evidence.length!==entry.ids.length)continue;
   if(entry.ids.some(id=>seen.has(id)||!byId.has(id)))continue;
   const sources=entry.ids.map(id=>byId.get(id));
   const legit=entry.evidence.every((quote,i)=>
     typeof quote==='string'&&quote.length>=10&&quote.length<=160&&
     sources[i].text.toLocaleLowerCase().includes(quote.trim().toLocaleLowerCase()));
   if(!legit)continue;
   const length=sources.reduce((n,c)=>n+c.end-c.start,0);
   if(length<.5||cumulative+length>budget+1e-4||length>300)continue;
   sources.forEach(x=>seen.add(x.id));cumulative+=length;
   stories.push({
      id:'story-llm-'+(stories.length+1),segments:sources.map(s=>({start:s.start,end:s.end})),
      start:Math.min(...sources.map(x=>x.start)),end:Math.max(...sources.map(x=>x.end)),
      title:titleFromText(sources[0].text),layout:'hybrid',focusX:50,
      method:'local-llm-reviewed-extractive',confidence:'low',status:'needs-review',
      outputSeconds:Math.round(length*10)/10,
      evidence:entry.evidence.map((quote,i)=>({time:sources[i].start,quote})),
      reviewReasons:[
        'Локальная LLM выбрала фрагменты по тексту; вам необходимо проверить контекст и монтаж вручную',
        ...(sources.length>1?['Несмежные части объединены — обязательно проверьте смысловые переходы']:[])
      ]
   });
 }
 return {clips:stories,summary:summarizeStoryPlan(stories,payload.duration),verified:true};
}
