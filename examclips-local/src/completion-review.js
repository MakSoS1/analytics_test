/**
 * Strict data contract for a LOCAL-only microtopic completeness reviewer.
 * This verifier is advisory: no LLM output automatically changes source timestamps.
 */
import {normalizeChunks} from './segments.js';
const LIMIT=14000;
export function buildReviewPayload(clip,chunks,duration,{margin=75}={}){
 if(!Number.isFinite(clip?.start)||!Number.isFinite(clip?.end)||clip.start>=clip.end)throw Error('Некорректная микротема');
 const rows=normalizeChunks(chunks,duration);
 const before=rows.filter(c=>c.end<=clip.start&&c.end>=clip.start-margin);
 const inside=rows.filter(c=>c.end>clip.start&&c.start<clip.end);
 const after=rows.filter(c=>c.start>=clip.end&&c.start<=clip.end+margin);
 const pack=xs=>xs.map(c=>({start:Math.round(c.start*10)/10,end:Math.round(c.end*10)/10,text:c.text})); 
 return {clip:{start:clip.start,end:clip.end,title:clip.title||'',duration:clip.end-clip.start},
   before:pack(before),inside:pack(inside),after:pack(after)};
}
export function reviewHasEvidence(raw,payload){
 if(!raw||typeof raw!=='object')return false;
 const content=payload.inside.map(x=>x.text).join(' ').toLowerCase().replace(/\s+/g,' ');
 const surrounding=[...payload.before,...payload.inside,...payload.after].map(x=>x.text).join(' ').toLowerCase().replace(/\s+/g,' ');
 if(!Array.isArray(raw.evidence)||raw.evidence.length===0||raw.evidence.length>5)return false;
 return raw.evidence.every(e=>typeof e==='string'&&e.length>=8&&e.length<=210 &&
    (content.includes(e.trim().toLowerCase().replace(/\s+/g,' '))||surrounding.includes(e.trim().toLowerCase().replace(/\s+/g,' '))));
}
export function normalizeReview(raw,payload){
 if(!raw||typeof raw!=='object')throw Error('AI-проверка вернула невалидный объект');
 const allowed=['complete','needs-context','unfinished','uncertain'];
 const verdict=allowed.includes(raw.verdict)?raw.verdict:'uncertain';
 const evidence=Array.isArray(raw.evidence)?raw.evidence.filter(x=>typeof x==='string').slice(0,5):[];
 const verified=reviewHasEvidence({...raw,evidence},payload);
 const safeDelta=x=>Number.isFinite(x)&&Math.abs(x)<=45?Math.round(x*10)/10:0;
 // A model's confidence has to be cross-checked with literal speech excerpts.
 const deltaStart=safeDelta(raw.suggestedStartDelta);
 const deltaEnd=safeDelta(raw.suggestedEndDelta);
 return {verdict:verified?verdict:'uncertain',
   confidence:verified&&Number.isFinite(raw.confidence)?Math.max(0,Math.min(1,raw.confidence)):0,
   evidence:verified?evidence:[],
   explanation:typeof raw.explanation==='string'?raw.explanation.slice(0,600):'',
   suggestedStartDelta:deltaStart,suggestedEndDelta:deltaEnd,
   evidenceVerified:verified,model:typeof raw.model==='string'?raw.model.slice(0,100):'',
   disclaimer:'Оценка локальной LLM — рекомендация; содержание и границы необходимо проверить.'};
}
export function prepareReviewRequest(payload){
 const serialized=JSON.stringify(payload);
 if(serialized.length>LIMIT)throw Error('Слишком большой контекст для локальной проверки');
 if(!payload.inside?.length)throw Error('Для AI-проверки требуется расшифровка выбранной микротемы');
 return serialized;
}
export function reviewPrompt(payload){
 const quoted=JSON.stringify(payload);
 return [
  'You are a conservative EDUCATIONAL LESSON AUDITOR, not a copywriter. Russian/English transcript.',
  'A full short lesson MUST make sense alone: topic introduced, coherent explanation, complete thought/result, no dangling pronouns or missing prerequisites. Duration 60-300 s is guidance, not proof.',
  'Before/after excerpts exist to detect whether selected boundaries cut an unfinished explanation.',
  'Return exactly one JSON object, no markdown, with keys: verdict (complete|needs-context|unfinished|uncertain), confidence (0..1), evidence (array of 1-3 LITERAL contiguous excerpts of at least 8 chars copied verbatim from the given transcript), explanation (short Russian), suggestedStartDelta and suggestedEndDelta (numbers in [-45,45] seconds; 0 if not required).',
  'Use only the supplied transcript, do not invent facts, topic names, quotes or conclusions. If boundary cannot be evaluated due to inaccurate ASR or missing context return uncertain. Judge actual ending rather than the presence of punctuation.',
  'Do not rewrite or summarize the transcript. The output is advisory and cannot autonomously approve publication.',
  'DATA:',quoted
 ].join('\n').slice(0,28000);
}
