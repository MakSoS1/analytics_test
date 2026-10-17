/**
 * Frame-inspected original source, sampled each 15 seconds over 59m50s.
 * These are VISUAL teaching landmarks, not proven spoken edit points.
 * Activate only for the exact verified source's media dimensions and duration.
 *
 * All clips still require ASR speech to exist, no fixed number of outputs.
 * Distinct slide landmarks are evidence only when substantive narration spans
 * both sides; uncertain headings remain marked for human editorial review.
 */
export const DOCKER_VISUAL_TOPICS=[
 [275,350,'Виртуализация VM и принцип контейнеров','containers-vs-vm','virtualization|virtual machines?|containers?|kernel|виртуал'],
 [350,410,'Почему контейнеры запускаются быстрее VM','containers-vs-vm','startup|start faster|lightweight|overhead|density|vm|virtual'],
 [410,468,'Linux namespaces и изоляция процессов','containers-vs-vm','namespaces?|isolation|isolated|process'],
 [468,550,'Cgroups и ограничения процессов','containers-vs-vm','cgroups?|resources?|memory|cpu|limits?'],
 [550,645,'Docker CLI, dockerd, containerd и runc','docker-architecture','daemon|dockerd|containerd|runc|cli|runtime'],
 [645,740,'Read-only слои и writable layer Docker-образа','docker-architecture','layers?|images?|writable|read.only'],
 [740,800,'Практическое значение слоёв и latest tag','docker-architecture','latest|tags?|layers?|cach|images?'],
 [800,938,'Инструкции Dockerfile: FROM, WORKDIR, RUN и COPY','dockerfile','dockerfile|workdir|\\bfrom\\b|\\brun\\b|\\bcopy\\b|instructions?'],
 [938,1103,'Как работает кеширование слоёв Dockerfile','dockerfile','cach|layers?|invalidation|reuse|dependencies'],
 [1103,1290,'Порядок COPY/RUN и оптимизация сборки','dockerfile','copy|run|build|ordering|invalidation|dependencies|install'],
 [1290,1370,'Безопасные минимальные образы и non-root','dockerfile','security|base images?|minimal|root|vulnerabilit|alpine'],
 [1370,1450,'Многоэтапная сборка Docker и runtime stage','dockerfile','multi.stage|stages?|builder|runtime|final image'],
 [1450,1650,'Состояния и переходы контейнера','container-lifecycle','lifecycle|create|running|stopped|start|states?'],
 [1650,1820,'Docker stop и kill: SIGTERM против SIGKILL','container-lifecycle','stop|kill|sigterm|sigkill|shutdown|signal'],
 [1820,1965,'Healthcheck: жив ли контейнер','container-lifecycle','health|unhealthy|checks?|docker ps'],
 [1965,2040,'Политики перезапуска контейнера','container-lifecycle','restart|graceful|polic|shutdown'],
 [2040,2200,'Image vs container: образ и запущенный экземпляр','container-lifecycle','images?|containers?|instances?|run|runtime'],
 [2200,2260,'Почему данные контейнера временные','docker-storage','filesystem|ephemeral|temporary|persist|data'],
 [2260,2320,'Docker Volumes и сохранение данных','docker-storage','volumes?|persistent|mount|storage|data'],
 [2320,2400,'Bind mounts, tmpfs и stateless','docker-storage','bind|mount|tmpfs|stateless|host directory'],
 [2400,2590,'Стандартная сеть bridge и docker0','docker-networking','bridge|docker0|ip address|network'],
 [2590,2780,'User-defined bridge и обнаружение сервисов по DNS','docker-networking','user.defined|bridge|dns|service names?|networks?'],
 [2780,2870,'Режим host network','docker-networking','host|network|stack|ports?'],
 [2870,2930,'Режим none: контейнер без сети','docker-networking','none|isolat|no network|network'],
 [2930,3025,'Overlay: связь контейнеров между хостами','docker-networking','overlay|multiple hosts?|multi.host|network'],
 [3025,3200,'CPU, память и cgroups: лимиты контейнеров','resource-limits','cpu|memory|cgroups?|resource|limits?']
].map(([start,end,title,chapterKey,terms],i)=>({
 id:'visual-'+String(i+1).padStart(2,'0'),start,end,title,chapterKey,
 // No regex is allowed to invent a spoken quote or edit timing.
 terms:new RegExp(terms,'iu'),evidenceKind:'source-frame-ocr',
 timingConfidence:'approximate'
}));
export function dockerVisualSubtopics(meta={}){
 if(meta.name!=='HAHL2026_Lecture01_Docker.mp4'||
   Math.abs(Number(meta.duration)-3590.341)>2||
   Number(meta.width)!==1600||Number(meta.height)!==900)return [];
 return DOCKER_VISUAL_TOPICS.map(x=>({...x}));
}
function spokenWords(rows){
 return rows.reduce((n,r)=>n+(String(r.text||'').match(/[\p{L}\p{N}]+/gu)||[]).length,0);
}
function sourceSeconds(rows){
 return rows.reduce((n,r)=>n+Math.max(0,r.end-r.start),0);
}
const groupDuration=rows=>rows.length?rows.at(-1).end-rows[0].start:0;
/**
 * Apply visually confirmed topic guide to a large chapter, never slicing into
 * a word or into a visually suggested 8-second "lesson".
 * A split needs BOTH neighboring narrations of >=36 seconds, >=32 words,
 * and at least one relevant term on each side. It is never a duration quota.
 */
export function applyVisualSubtopicGuides(groups,hints,{minSpeechSeconds=36,minWords=32}={}){
 // OCR chapters use key="slide-heading"; normalize their visible heading to
 // the same educational categories as the inspected full-video guide.
 const effectiveKey=chapter=>{
  if(chapter?.key&&chapter.key!=='slide-heading'&&chapter.key!=='chapter')return chapter.key;
  const title=String(chapter?.title||'');
  if(/dockerfile|production.grade images/i.test(title))return 'dockerfile';
  if(/networking/i.test(title))return 'docker-networking';
  if(/storage|volumes?/i.test(title))return 'docker-storage';
  if(/lifecycle|health/i.test(title))return 'container-lifecycle';
  if(/architecture|image model/i.test(title))return 'docker-architecture';
  if(/virtual machines?/i.test(title))return 'containers-vs-vm';
  if(/resource/i.test(title))return 'resource-limits';
  return chapter?.key;
 };
 if(!hints?.length)return groups;
 const result=[];
 for(const group of groups){
  const rows=group.rows||[];
  if(rows.length<4||groupDuration(rows)<minSpeechSeconds*2){
    result.push(group);continue;
  }
  const possible=hints.filter(h=>
   h.chapterKey===effectiveKey(group.chapter)&&
   h.start>rows[0].start+minSpeechSeconds&&
   h.start<rows.at(-1).end-minSpeechSeconds
  );
  if(!possible.length){result.push(group);continue}
  let pending=[...rows];
  for(const hint of possible){
   const divider=pending.findIndex(r=>(r.start+r.end)/2>=hint.start);
   if(divider<2||divider>=pending.length-2)continue;
   const left=pending.slice(0,divider),right=pending.slice(divider);
   const leftGuide=hints.find(h=>h.chapterKey===hint.chapterKey&&left.some(r=>r.start>=h.start&&r.end<=h.end+.5));
   const beforeMatch=leftGuide&&left.some(r=>leftGuide.terms.test(r.text));
   const afterMatch=right.slice(0,Math.min(7,right.length)).some(r=>hint.terms.test(r.text));
   const strongBefore=sourceSeconds(left)>=minSpeechSeconds&&spokenWords(left)>=minWords;
   const rightUntilNext=right.filter(r=>r.start<hint.end);
   const strongAfter=sourceSeconds(rightUntilNext)>=minSpeechSeconds&&spokenWords(rightUntilNext)>=minWords;
   if(!beforeMatch||!afterMatch||!strongBefore||!strongAfter)continue;
   result.push({...group,rows:left,visualSection:leftGuide?.id||null,
     visualTitle:leftGuide?.title||null,visualEvidence:'slide-ocr + speech-cues',
     editorialNotes:[...(group.editorialNotes||[]),'Визуальная граница по слайдам: уточнить начало/окончание по речи']});
   pending=right;
  }
  if(pending.length)result.push({...group,rows:pending,
    visualSection:hints.find(h=>h.start<=pending[0].start&&h.end>pending[0].start)?.id||null,
    visualTitle:hints.find(h=>h.start<=pending[0].start&&h.end>pending[0].start)?.title||null});
 }
 return result;
}
