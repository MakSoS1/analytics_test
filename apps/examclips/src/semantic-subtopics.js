/**
 * Full-lecture second pass: find independently and repeatedly taught concepts
 * WITHIN broad slide chapters. A single keyword never opens a new short.
 * Use stable source ASR windows on both sides and minimum context.
 * No preset count and no maximum clip length.
 */
import {rowLessonIdentity,lessonIdentity} from './lesson-identity.js';
const EXERCISE=/(?:решим\s+(?:эту|следующую|одну)?\s*задач|практическ\w*\s+задач|worked\s+example|let'?s\s+solve|solve\s+this\s+problem|proof\s+of\s+the\s+theorem)/iu;
const EXERCISE_END=/(?:задача\s+решена|таким\s+образом\s+получили\s+ответ|problem\s+solved|that\s+completes\s+the\s+(?:proof|solution))/iu;
const wordCount=rows=>rows.reduce((n,x)=>n+(x.text.match(/[\p{L}\p{N}]+/gu)||[]).length,0);
const span=rows=>rows.length?rows.at(-1).end-rows[0].start:0;
function majority(rows,chapter){
 const scores=new Map();
 for(const row of rows){
   const id=rowLessonIdentity(row,chapter);
   if(!id?.specific)continue;
   const x=scores.get(id.key)||{...id,hits:0};
   x.hits++;scores.set(id.key,x);
 }
 return [...scores.values()].sort((a,b)=>b.hits-a.hits)[0]||null;
}
function windowBefore(rows,i,seconds=72){
 const at=rows[i].start;
 return rows.slice(0,i).filter(r=>r.end>=at-seconds);
}
function windowAfter(rows,i,seconds=72){
 const at=rows[i].start;
 return rows.slice(i).filter(r=>r.start<=at+seconds);
}
function wholeExercise(rows){
 const begins=rows.some(r=>EXERCISE.test(r.text));
 const finishes=rows.some(r=>EXERCISE_END.test(r.text));
 return begins&&!finishes;
}
function mark(group,rows){
 const identity=majority(rows,group.chapter);
 return {...group,rows,verifiedConcept:identity?.hits>=2?identity.key:null,
   verifiedTitle:identity?.hits>=2?identity.title:null,
   editorialNotes:[...(group.editorialNotes||[])]};
}
/** A single 6-minute chapter may yield 4 complete, evidenced concepts. */
export function refineSubtopics(groups,{minSeconds=48,minWords=35}={}){
 const result=[];
 for(const group of groups){
   const rows=group.rows||[];
   if(rows.length<6||span(rows)<minSeconds*2||wholeExercise(rows)){
     result.push(group);continue;
   }
   let start=0;
   for(let i=2;i<rows.length-2;i++){
     const left=rows.slice(start,i),right=rows.slice(i);
     if(span(left)<minSeconds||span(right)<minSeconds||
       wordCount(left)<minWords||wordCount(right)<minWords)continue;
     const before=windowBefore(rows,i),after=windowAfter(rows,i);
     const prior=majority(before,group.chapter),following=majority(after,group.chapter);
     if(!prior||!following||prior.key===following.key||
       prior.hits<2||following.hits<2)continue;
     // The concepts must be DOMINANT on separate sides, not a single
     // stray word in an illustration or repeated Dockerfile introduction.
     const leftIdentity=majority(left.slice(-10),group.chapter);
     const rightIdentity=majority(right.slice(0,10),group.chapter);
     if(leftIdentity?.key!==prior.key||rightIdentity?.key!==following.key)continue;
     // Look-ahead ensures no 20-second fragment has been carved out.
     const first=right.slice(0,Math.min(8,right.length));
     if(span(first)<Math.min(30,minSeconds*.6))continue;
     // When solving a continuous exercise, keep the reasoning together.
     if(wholeExercise(left)||wholeExercise(right))continue;
     const previous=mark(group,left);
     result.push(previous);
     start=i;
     // Skip already-consumed left contexts; subsequent boundaries are tested
     // against a fresh left window and the original source timestamps.
     i=Math.max(i,start+1);
   }
   const remaining=rows.slice(start);
   if(remaining.length)result.push(mark(group,remaining));
 }
 return result;
}
