/**
 * Source-evidenced teaching concept identity.
 *
 * A generic word (Docker, container, image) is context, not a lesson title.
 * In particular Dockerfile speech never becomes "What is a container" unless
 * the source explicitly defines containers AND the chapter is about them.
 * The same identity powers splitting, merging and the card title.
 */
const CONTAINER_DEFINITION=/\b(?:what\s+(?:is|are)\s+(?:a\s+)?containers?|containers?\s+(?:is|are)\s+(?:an?\s+)?(?:isolated|lightweight|process|environment)|контейнер(?:ы)?\s+(?:это|представля(?:ют|ет))|что\s+такое\s+контейнер)\b/iu;
const VM=/(?:\b(?:virtual\s+machines?|hypervisor|hypervisors?|vm\s+versus\s+container|containers?\s+(?:vs\.?|versus)\s+vms?)\b|виртуальн\w*\s+машин|гипервизор)/iu;
const INSTRUCTIONS=/(?:\b(?:dockerfile|docker\s+file|docker\s+build|build\s+context|buildkit|workdir|entrypoint)\b|\b(?:FROM|RUN|COPY|ADD|CMD|ENV|ARG|EXPOSE|USER|HEALTHCHECK)\b|докерфайл|инструкци\w*\s+dockerfile)/u;
const BUILDCACHE=/(?:\b(?:build\s+cache|layer\s+cach(?:e|ing)|cache\s+invalidat(?:e|ion)|docker\s+build\s+--no-cache|cached\s+layers?)\b|кеширован\w*\s+сло|кэш\w*\s+сборк)/iu;
const MULTISTAGE=/(?:\b(?:multi[\s-]?stage|multiple\s+build\s+stages?|build\s+stage|scratch\s+image)\b|многоэтапн\w*\s+сборк)/iu;
const DOCKER_LAYERS=/(?:\b(?:image\s+layers?|layered\s+filesystem|read.only\s+layers?|copy.on.write)\b|сло\w*\s+образ|слоист\w*\s+файл)/iu;
const DOCKER_SECURITY=/(?:\b(?:rootless|non.root\s+user|image\s+scanning|least\s+privilege|vulnerabilit(?:y|ies)|supply\s+chain\s+securit)\b|уязвимост\w*\s+образ|безопасност\w*\s+сборк)/iu;
const DOCKER_NETWORK=/(?:\b(?:bridge\s+network|overlay\s+network|host\s+network|port\s+mapping|docker0)\b|сеть\s+docker|сетев\w*\s+режим)/iu;
const DOCKER_STORAGE=/(?:\b(?:bind\s+mount|docker\s+volume|persistent\s+storage)\b|том\w*\s+docker|хранен\w*\s+данн)/iu;
const DOCKER_LIFECYCLE=/(?:\b(?:container\s+lifecycle|docker\s+(?:start|stop|kill)|health\s?check|sigterm|sigkill)\b|жизненн\w*\s+цикл\s+контейнер)/iu;
const CLEAN=/\s+/gu;
const RULES={
 'dockerfile':[
  ['dockerfile-multistage','Многоэтапная сборка образа',MULTISTAGE],
  ['dockerfile-cache','Кеширование слоёв при сборке Dockerfile',BUILDCACHE],
  ['dockerfile-security','Безопасная сборка Docker-образов',DOCKER_SECURITY],
  ['dockerfile-instructions','Инструкции Dockerfile: FROM, RUN и COPY',INSTRUCTIONS],
  ['dockerfile-layers','Как формируются слои Docker-образа',DOCKER_LAYERS]
 ],
 'containers-vs-vm':[
  ['virtual-machines','Контейнеры и виртуальные машины',VM],
  ['container-definition','Что такое контейнер',CONTAINER_DEFINITION]
 ]
};
const FALLBACK={
 'dockerfile':'Dockerfile: создание и сборка образа',
 'docker-images':'Образы и слои Docker',
 'docker-architecture':'Архитектура и компоненты Docker',
 'docker-networking':'Сетевые режимы Docker',
 'container-lifecycle':'Жизненный цикл Docker-контейнера',
 'docker-storage':'Хранение данных Docker',
 'containers-vs-vm':'Контейнеры и виртуальные машины',
 'resource-limits':'Ограничение ресурсов контейнера'
};
function evidence(text,chapterKey){
 const corpus=String(text||'');
 const chapter=String(chapterKey||'');
 const rules=RULES[chapter];
 if(rules){
   const found=rules.filter(([, ,re])=>re.test(corpus));
   // An explicit Dockerfile instruction may appear with multi-stage cache;
   // precedence is distinctive techniques > generic commands.
   if(found.length){
     const [key,title]=found[0];
     return {key,title,specific:true,chapter};
   }
   if(chapter==='dockerfile')return {key:'dockerfile-general',title:FALLBACK.dockerfile,specific:false,chapter};
   return {key:'containers-general',title:FALLBACK['containers-vs-vm'],specific:false,chapter};
 }
 if(DOCKER_NETWORK.test(corpus)&&chapter==='docker-networking')
   return {key:'docker-networking',title:FALLBACK['docker-networking'],specific:false,chapter};
 if(DOCKER_STORAGE.test(corpus)&&chapter==='docker-storage')
   return {key:'docker-storage',title:FALLBACK['docker-storage'],specific:false,chapter};
 if(DOCKER_LIFECYCLE.test(corpus)&&chapter==='container-lifecycle')
   return {key:'container-lifecycle',title:FALLBACK['container-lifecycle'],specific:false,chapter};
 if(CONTAINER_DEFINITION.test(corpus)&&!['dockerfile','docker-images','docker-architecture'].includes(chapter))
   return {key:'container-definition',title:'Что такое контейнер',specific:true,chapter};
 if(VM.test(corpus))return {key:'virtual-machines',title:'Контейнеры и виртуальные машины',specific:true,chapter};
 return null;
}
export function rowLessonIdentity(row,chapter){
 return evidence(row?.text,chapter?.key);
}
export function lessonIdentity(rows,chapter){
 const corpus=(rows||[]).map(r=>String(r?.text||'').replace(CLEAN,' ').trim()).filter(Boolean);
 const key=chapter?.key;
 const scores=new Map();
 // Full group evidence is more reliable than single-line topic keywords.
 for(const text of corpus){
   const identity=evidence(text,key);
   if(!identity)continue;
   const score=identity.specific?3:1;
   const entry=scores.get(identity.key)||{...identity,score:0,hits:0};
   entry.score+=score;entry.hits++;scores.set(identity.key,entry);
 }
 const ranked=[...scores.values()].sort((a,b)=>b.score-a.score||b.hits-a.hits);
 const best=ranked[0];
 if(best&&best.specific)return best;
 if(key&&FALLBACK[key])return {key:key==='dockerfile'?'dockerfile-general':key,title:FALLBACK[key],specific:false,chapter:key};
 return best||null;
}
export function distinctVerifiedConcept(a,b){
 const left=lessonIdentity(a.rows||[],a.chapter),right=lessonIdentity(b.rows||[],b.chapter);
 return Boolean(left?.specific&&right?.specific&&left.key!==right.key&&
   // Require more than a single incidental mention on both sides
   (a.rows?.length||0)>=2&&(b.rows?.length||0)>=2&&
   (a.rows.at(-1).end-a.rows[0].start)>=30&&
   (b.rows.at(-1).end-b.rows[0].start)>=30);
}
