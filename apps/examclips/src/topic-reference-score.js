/**
 * Scores planned microtopics against a HUMAN topic map of the same lecture.
 * Reference: {topics:[{title,start,end,kind:'teaching'|'recap'|'qa',group?,related?}],organizational:[{start,end}]}.
 * Measures what a viewer cares about: is each topic in one video, does a video
 * hold one topic, is anything taught missing, are there empty videos.
 */
import {sourceSegments,storyDuration} from './selective-stories.js';

const overlap=(segments,start,end)=>segments.reduce((n,s)=>n+Math.max(0,Math.min(s.end,end)-Math.max(s.start,start)),0);

export function scoreAgainstReference(clips,reference,{whole=.85,present=25,tolerance=8}={}){
 const topics=reference?.topics||[];
 if(!topics.length)throw Error('Required: a nonempty human topic map');
 const pieces=clips.map(c=>sourceSegments(c));
 // A Q&A answer belongs to the topic it explains; subtopics of a group may share a video.
 const unit=t=>t.kind==='qa'&&t.related?(topics.find(x=>x.title===t.related)?.group||t.related):(t.group||t.title);
 const perTopic=topics.map(t=>{
  const length=t.end-t.start;
  const shares=pieces.map(p=>overlap(p,t.start,t.end)/length);
  const best=shares.reduce((b,v,i)=>v>shares[b]?i:b,0);
  const relatedTopic=t.kind==='qa'&&t.related?topics.find(x=>x.title===t.related):null;
  const relatedClip=relatedTopic?pieces.map(p=>overlap(p,relatedTopic.start,relatedTopic.end)).reduce((b,v,i,a)=>v>a[b]?i:b,0):null;
  return {title:t.title,kind:t.kind,seconds:Math.round(length),whole:shares[best]>=whole,bestShare:+shares[best].toFixed(2),
   clip:best+1,covered:+pieces.reduce((n,p)=>n+overlap(p,t.start,t.end),0).toFixed(1)/length,
   attachedToTopic:relatedTopic?shares[best]>=.5&&best===relatedClip:null};
 });
 const perClip=clips.map((c,i)=>{
  const seconds=storyDuration(c);
  const inside=topics.map(t=>({t,s:overlap(pieces[i],t.start,t.end)}))
   .filter(x=>x.s>=Math.min(present,(x.t.end-x.t.start)*.5));
  const units=[...new Set(inside.map(x=>unit(x.t)))];
  const taught=inside.reduce((n,x)=>n+x.s,0);
  return {index:i+1,title:c.title,seconds:Math.round(seconds),units:units.length,
   topics:inside.map(x=>x.t.title),focused:units.length===1,empty:taught<seconds*.4,
   firstSentence:c.boundaryEvidence?.first||''};
 });
 const teaching=topics.filter(t=>t.kind!=='qa');
 const totalTeaching=teaching.reduce((n,t)=>n+t.end-t.start,0);
 const coveredTeaching=teaching.reduce((n,t)=>n+pieces.reduce((m,p)=>m+overlap(p,t.start,t.end),0),0);
 const midSentence=perClip.filter(c=>/^[a-zа-яё]/u.test(c.firstSentence.trim())).length;
 // A video starts where a topic starts (±tolerance), not one sentence early or late.
 const starts=topics.map(t=>t.start);
 const startHits=clips.filter(c=>starts.some(s=>Math.abs(sourceSegments(c)[0].start-s)<=tolerance)).length;
 const clean=perTopic.filter(t=>t.whole&&perClip[t.clip-1].focused&&!perClip[t.clip-1].empty).length;
 return {
  summary:{clips:clips.length,referenceTopics:topics.length,
   cleanTopics:clean,
   wholeTopics:perTopic.filter(t=>t.whole).length,
   startPrecision:+(startHits/Math.max(1,clips.length)).toFixed(2),
   focusedClips:perClip.filter(c=>c.focused).length,
   multiTopicClips:perClip.filter(c=>c.units>1).length,
   emptyClips:perClip.filter(c=>c.empty).length,
   qaAttached:perTopic.filter(t=>t.attachedToTopic).length+'/'+perTopic.filter(t=>t.attachedToTopic!==null).length,
   teachingCoverage:+(coveredTeaching/totalTeaching).toFixed(3),
   midSentenceStarts:midSentence,
   longestClipSeconds:Math.max(0,...perClip.map(c=>c.seconds)),
   shortestClipSeconds:Math.min(...perClip.map(c=>c.seconds))},
  perTopic,perClip,
  note:'Scores depend on one manual reference; they are not pedagogical guarantees.'};
}
