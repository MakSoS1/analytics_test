/**
 * Full-lecture ASR audit for the private Windows runner.
 * All produced reports remain local/private. No fabricated transcripts.
 * node scripts/audit-real-lecture.mjs transcript.json output-directory
 */
import fs from 'node:fs';
import path from 'node:path';
import {planCompleteTopics} from '../src/complete-topics.js';
import {lectureVisualReference} from '../src/lecture-outline.js';
import {dockerVisualSubtopics} from '../src/visual-subtopic-hints.js';
import {buildVerifiedLessonScreenplays} from '../src/lesson-screenplay.js';
import {sourceSegments,storyDuration} from '../src/selective-stories.js';

const CHECKS=[
 ['container definition', /\b(?:container is|containers are|isolated process|linux namespaces)\b/i,'containers-vs-vm'],
 ['VM difference', /\b(?:virtual machin|hypervisor|virtuali[sz]ation|guest operating system)\b/i,'containers-vs-vm'],
 ['Docker architecture', /\b(?:docker daemon|docker engine|docker client|containerd|runc)\b/i,'docker-architecture'],
 ['Image layers', /\b(?:image layer|layered filesystem|read.only layer|copy.on.write)\b/i,'docker-architecture'],
 ['Dockerfile instructions', /\b(?:dockerfile|docker file|from instruction|run instruction|copy instruction|build context)\b/i,'dockerfile'],
 ['Layer caching', /\b(?:build cache|layer cach|cache invalid|reuse a layer|cached layer)\b/i,'dockerfile'],
 ['Multi-stage builds', /\b(?:multi[ -]?stage|builder stage|final stage|multiple stages)\b/i,'dockerfile'],
 ['Image security', /\b(?:rootless|vulnerabilit|non.root user|image scan|least privilege)\b/i,'dockerfile'],
 ['Container lifecycle', /\b(?:docker stop|docker kill|sigterm|sigkill|container lifecycle|running state)\b/i,'container-lifecycle'],
 ['Health checks', /\b(?:health.?check|container health|unhealthy)\b/i,'container-lifecycle'],
 ['Volumes', /\b(?:docker volume|named volume|volume mount|persistent storage)\b/i,'docker-storage'],
 ['Bind mounts/stateless', /\b(?:bind mount|stateless|host directory)\b/i,'docker-storage'],
 ['Bridge network', /\b(?:bridge network|docker0|bridge mode)\b/i,'docker-networking'],
 ['Host/none network', /\b(?:host network|none network|network mode host)\b/i,'docker-networking'],
 ['Overlay network', /\b(?:overlay network|overlay mode|across hosts)\b/i,'docker-networking'],
 ['Port mapping', /\b(?:port mapping|port forward|publish port|expose port)\b/i,'docker-networking'],
 ['CPU/memory limits', /\b(?:cpu limit|memory limit|resource isolation|cgroup|out of memory)\b/i,'resource-limits']
];
const [inputFile,outputDir] = process.argv.slice(2);
if(!inputFile||!outputDir)throw Error('Usage: node scripts/audit-real-lecture.mjs ASR.json OUTPUT_DIRECTORY');
const input=JSON.parse(fs.readFileSync(inputFile,'utf8'));
const rows=(input.rows||[]).filter(x=>x.text&&x.end>x.start).sort((a,b)=>a.start-b.start);
const duration=3590.341;
const chapters=lectureVisualReference({name:'HAHL2026_Lecture01_Docker.mp4',duration,width:1600,height:900});
const guide=dockerVisualSubtopics({name:'HAHL2026_Lecture01_Docker.mp4',duration,width:1600,height:900});
const baseline=planCompleteTopics(rows,duration,{chapters});
const plan=planCompleteTopics(rows,duration,{chapters,visualHints:guide});
const clips=buildVerifiedLessonScreenplays(plan.clips,rows);
const cuts=clips.map((c,i)=>({index:i+1,id:c.id,title:c.title,start:c.start,end:c.end,
  seconds:+storyDuration(c).toFixed(1),chapter:c.chapter?.key||'unknown',
  visualSection:c.visualSection||null,segments:sourceSegments(c),quality:c.screenplay?.quality}));
const clipsAt=(r)=>clips.filter(c=>sourceSegments(c).some(s=>Math.min(r.end,s.end)-Math.max(r.start,s.start)>.1));
const checks=CHECKS.map(([name,re,chapter])=>{
 const hits=rows.filter(r=>re.test(r.text));
 const represented=new Set(hits.flatMap(r=>clipsAt(r).map(c=>c.id)));
 return {name,chapter,sourceMentions:hits.length,representedIn:represented.size,
  firstSourceMentions:hits.slice(0,8).map(r=>({start:r.start,end:r.end,quote:r.text}))};
});
const visualReview=guide.map(hint=>{
 const sectionRows=rows.filter(r=>(r.start+r.end)/2>=hint.start&&(r.start+r.end)/2<hint.end);
 const matchingSpeech=sectionRows.filter(r=>hint.terms.test(r.text));
 const linked=cuts.filter(c=>c.visualSection===hint.id);
 const overlappingVideos=cuts.filter(c=>c.start<hint.end&&c.end>hint.start);
 return {id:hint.id,title:hint.title,start:hint.start,end:hint.end,
   chapter:hint.chapterKey,sourceRows:sectionRows.length,speechCues:matchingSpeech.length,
   directlySupportedVideoIds:linked.map(c=>c.id),
   overlappingVideoIds:overlappingVideos.map(c=>c.id),
   status:!sectionRows.length?'ASR_NOT_PRESENT':
     linked.length?'SEPARATE_VISUAL_LESSON':
     matchingSpeech.length?'POSSIBLE_OVERMERGE_REVIEW':'NO_MATCHING_ASR_CUE'};
});
const chapterAudit=chapters.map(ch=>{
 const own=cuts.filter(c=>ch.start===clips[c.index-1].chapter?.start);
 const found=checks.filter(c=>c.chapter===ch.key&&c.sourceMentions);
 const visual=visualReview.filter(h=>h.chapter===ch.key);
 return {start:ch.start,end:ch.end,key:ch.key,title:ch.title,videoCount:own.length,
  sourceSentences:rows.filter(r=>r.start<ch.end&&r.end>ch.start).length,
  conceptsWithEvidence:found.length,visualCandidates:visual.length,
  visualCandidatesWithSpeech:visual.filter(h=>h.speechCues).length,
  visuallyDistinctVideos:visual.filter(h=>h.directlySupportedVideoIds.length).length,
  overmerged:own.length===1&&(found.length>=3||visual.filter(h=>h.speechCues).length>=3)&&own[0].seconds>180};
});
const uncovered=rows.filter(r=>clipsAt(r).length===0);
const distinctNames=new Map();
for(const c of cuts)distinctNames.set(c.title,[...(distinctNames.get(c.title)||[]),c.index]);
const repeatedTitles=[...distinctNames].filter(([k,v])=>v.length>1);
const oversized=cuts.filter(c=>c.seconds>=240&&checks.filter(t=>t.chapter===c.chapter&&t.sourceMentions).length>=3);
const report={source:'private original lecture ASR',transcriptionModel:input.model,
 transcriptChunks:rows.length,duration,summary:plan.summary,
 baselineWithoutVisualGuides:{videoCount:baseline.clips.length,summary:baseline.summary},
 originalVisualGuide:visualReview,
 videoCount:cuts.length,videos:cuts,chapters:chapterAudit,concepts:checks,
 repeatedTitles,uncoveredRows:uncovered.length,
 uncoveredEvidence:uncovered.slice(0,120),oversized:oversized.map(c=>c.index),
 warning:'Keyword evidence is a screening tool, not proof of pedagogical completeness.'};
fs.mkdirSync(outputDir,{recursive:true});
fs.writeFileSync(path.join(outputDir,'audit.json'),JSON.stringify(report,null,2),'utf8');
const hh=n=>{n=Math.floor(n);return [Math.floor(n/3600),Math.floor(n/60)%60,n%60].map(x=>String(x).padStart(2,'0')).join(':');};
const lines=[
 '# Docker lecture: real full-ASR coverage audit','',
 'Source: private MP4, aligned speech, inspected visual chapter map.',
 'ASR sentences: **'+rows.length+'**; microvideos: **'+cuts.length+'**.',
 'Before visual-subtopic refinement: **'+baseline.clips.length+'**; after: **'+cuts.length+'**.',
 'Candidate microtopics: '+plan.summary.rawTopicCandidates+
 '; merged: '+plan.summary.editorialMerges+'; excluded: '+plan.summary.rejectedFragments+'.',
 'Speech rows not represented in any clip: '+uncovered.length+'.',
 'Overmerged large videos (possible): '+(oversized.map(c=>c.index).join(', ')||'none')+'.',
 'Repeated titles: '+JSON.stringify(repeatedTitles),'',
 '## Per-chapter results','',
 '| Position | Chapter | Videos | Original visual concepts | Speech-supported concepts | Overmerge suspect |',
 '|---|---|---:|---:|---:|---|'
];
for(const c of chapterAudit)lines.push('| '+hh(c.start)+'–'+hh(c.end)+' | '+c.title+' | '+c.videoCount+' | '+c.visualCandidates+' | '+c.visualCandidatesWithSpeech+' | '+(c.overmerged?'YES':'—')+' |');
lines.push('','## All visually observed subtopics: video vs original speech','');
for(const v of visualReview)lines.push('- '+v.id+' '+hh(v.start)+'–'+hh(v.end)+' **'+v.title+'**: '+v.status+
  '; ASR rows '+v.sourceRows+'; matching speech cues '+v.speechCues+'; overlaps '+v.overlappingVideoIds.length+' videos.');
lines.push('','## Every video','',
 '| # | Title | Source | Video length | Confirmed screenplay |',
 '|---:|---|---|---:|---|');
for(const c of cuts)lines.push('| '+c.index+' | '+c.title+' | '+hh(c.start)+'–'+hh(c.end)+' | '+hh(c.seconds)+' | '+(c.quality?.fullySupported?'Yes':'Needs review')+' |');
lines.push('','## Concepts by evidence','');
for(const c of checks)lines.push('- '+c.name+': '+c.sourceMentions+' spoken mentions; in '+c.representedIn+' videos.');
lines.push('','## Uncovered speech (first 120 ASR rows)','');
for(const r of uncovered.slice(0,120))lines.push('- '+hh(r.start)+'–'+hh(r.end)+' '+r.text.slice(0,200));
fs.writeFileSync(path.join(outputDir,'audit.md'),lines.join('\n'),'utf8');
console.log('REAL_LECTURE_AUDIT',JSON.stringify({clips:cuts.length,asrRows:rows.length,
 raw:plan.summary.rawTopicCandidates,baseline:baseline.clips.length,
 additionalVisualSplits:plan.summary.visualEvidenceSplitCount||0,
 merged:plan.summary.editorialMerges,
 chapterCounts:chapterAudit.map(c=>[c.key,c.videoCount,c.conceptsWithEvidence]),
 repeatedTitles,oversized:oversized.map(c=>c.index),uncoveredSpeech:uncovered.length},null,2));
