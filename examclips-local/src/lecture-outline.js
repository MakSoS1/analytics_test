/**
 * Chapter hierarchy, validated against original slide sequence when available.
 *
 * A visual outline is contextual evidence, not proof of spoken explanations.
 * The ASR transcript is always authoritative for the final editable clip range.
 * The only bundled lecture profile was inspected against the ORIGINAL uploaded
 * 59m50s ITMO Docker recording (1600x900), NOT guessed from the course agenda.
 */
const DOCKER_PROFILE=[
 [0,228,'Вводная и организация','introduction'],
 [228,490,'Понятие контейнера и сравнение с VM','containers-vs-vm'],
 [490,612,'Архитектура Docker','docker-architecture'],
 [612,770,'Образы Docker и слои','docker-images'],
 [770,1255,'Dockerfile: сборка, слои и кеширование','dockerfile'],
 [1255,1435,'Безопасность и сборка образов','docker-security'],
 [1435,1850,'Жизненный цикл и диагностика контейнеров','container-lifecycle'],
 [1850,2150,'Dockerfile: практические варианты','dockerfile'],
 [2150,2395,'Сохранение данных: volumes и bind mounts','docker-storage'],
 [2395,3030,'Сети Docker: bridge, host, none и overlay','docker-networking'],
 [3030,3240,'Ограничение ресурсов контейнеров','resource-limits'],
 [3240,3310,'Выводы и повторение','recap'],
 [3310,3590.341,'Повтор материала о сетях','docker-networking']
];
function interval(row){return {start:row[0],end:row[1],title:row[2],key:row[3],source:'visual-manually-inspected',confidence:'approximate'};}
export function lectureVisualReference({name='',duration=0,width=0,height=0}={}){
 // Both filename and physical media parameters are required, so unrelated
 // uploads are never force-fit to this lecture's hand-inspected outline.
 if(!/^(?:HAHL2026_Lecture01_Docker)(?:\.mp4)$/i.test(String(name))||
   Math.abs(duration-3590.341)>2||width!==1600||height!==900)return [];
 return DOCKER_PROFILE.map(interval);
}
const INTRO=/(?:about\s+me|course\s+(?:outline|schedule)|lecture\s+\d+\s*(?:brief|intro)|введение\s+в\s+курс|обо\s+мне|о\s+себе|план\s+лекц)/iu;
const WRAP=/(?:conclusion|summary|recap|выводы|итоги|повторение)/iu;
export function normalizeSlideChapters(rows=[],duration=Infinity){
 const entries=(rows||[]).map(s=>({start:Number(s.start),end:Number(s.end),
   title:String(s.title||'').trim().slice(0,100),key:String(s.key||''),
   source:String(s.source||'slide-ocr'),confidence:s.confidence||'low'}))
  .filter(s=>Number.isFinite(s.start)&&Number.isFinite(s.end)&&
    s.start>=0&&s.end>s.start&&s.end<=duration+.5&&s.title)
  .sort((a,b)=>a.start-b.start);
 const normalized=[];
 for(const entry of entries){
   if(normalized.length&&entry.start<normalized.at(-1).end)
     normalized.at(-1).end=entry.start;
   if(entry.end>entry.start)normalized.push({...entry,key:entry.key||
     (INTRO.test(entry.title)?'introduction':WRAP.test(entry.title)?'recap':'chapter')});
 }
 return normalized;
}
export function chapterForTime(chapters,at){
 return chapters.find(c=>at>=c.start&&at<c.end)||null;
}
/** Nearest chapter boundary, only when we already have valid source ASR cues. */
export function visualBoundaryBetween(chapters,prior,next,{tolerance=18}={}){
 if(!chapters?.length||!(next.start>=prior.end))return null;
 const boundaries=chapters.filter(c=>c.start>prior.start&&
   Math.abs(c.start-next.start)<=tolerance&&c.start<next.end+.5);
 return boundaries[0]||null;
}
export function chapterSkipped(clip,chapters){
 if(!chapters.length)return false;
 const midpoint=(clip.start+clip.end)/2;
 return chapterForTime(chapters,midpoint)?.key==='introduction';
}
