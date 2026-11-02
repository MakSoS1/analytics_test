/** Runs the app's planner on a local transcript and scores it against a manual topic map.
 * node scripts/evaluate-topic-plan.mjs TRANSCRIPT_JSON REFERENCE_JSON [STRUCTURE_JSON] [--details]
 * STRUCTURE_JSON may be a render-plan.json/lecture structure with {chapters,cuts|sceneCuts}.
 * Transcripts and references of private lectures stay local; nothing is uploaded.
 */
import {readFileSync} from 'node:fs';
import {planGeneralTopics} from '../src/general-topics.js';
import {buildVerifiedLessonScreenplays} from '../src/lesson-screenplay.js';
import {scoreAgainstReference} from '../src/topic-reference-score.js';
const args=process.argv.slice(2),details=args.includes('--details');
const [transcript,referenceFile,structureFile]=args.filter(a=>!a.startsWith('--'));
if(!transcript||!referenceFile)throw Error('Expected TRANSCRIPT_JSON REFERENCE_JSON [STRUCTURE_JSON]');
const data=JSON.parse(readFileSync(transcript,'utf8')),rows=data.rows||data.chunks;
const structure=structureFile?JSON.parse(readFileSync(structureFile,'utf8')):{};
const duration=Number(data.duration)||Math.max(...rows.map(r=>r.end))+1;
const plan=planGeneralTopics(rows,duration,{chapters:structure.chapters||[],sceneCuts:structure.cuts||structure.sceneCuts||[]});
const clips=buildVerifiedLessonScreenplays(plan.clips,rows);
const score=scoreAgainstReference(clips,JSON.parse(readFileSync(referenceFile,'utf8')));
const time=t=>Math.floor(t/60)+':'+String(Math.floor(t%60)).padStart(2,'0');
console.log(JSON.stringify(score.summary));
if(details){
 for(const c of score.perClip){
  const parts=(clips[c.index-1].segments||[]).map(s=>time(s.start)+'-'+time(s.end));
  const span=parts.length>3?parts[0]+' … '+parts.at(-1)+' ('+parts.length+')':parts.join(', ');
  console.log('#'+c.index,c.seconds+'s',c.focused?'':'['+c.units+' topics]',c.empty?'[EMPTY]':'','«'+c.title+'»',span,'\n    ',c.topics.join(' | '));
 }
 for(const t of score.perTopic.filter(t=>!t.whole||t.attachedToTopic===false))
  console.log('NOT WHOLE:',t.title,'best clip #'+t.clip,'share',t.bestShare,t.attachedToTopic===false?'(Q&A not attached)':'');
}
