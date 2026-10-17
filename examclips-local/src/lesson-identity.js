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
const INSTRUCTIONS=/(?:\b(?:workdir|entrypoint|build\s+context|copy\s+--from)\b|\b(?:FROM|RUN|COPY|ADD|CMD|ENV|ARG|EXPOSE|USER|HEALTHCHECK)\b|инструкци\w*\s+dockerfile)/u;
const BUILDCACHE=/(?:\b(?:build\s+cache|layer\s+cach(?:e|ing)|cache\s+invalidat(?:e|ion)|docker\s+build\s+--no-cache|cached\s+layers?)\b|кеширован\w*\s+сло|кэш\w*\s+сборк)/iu;
const MULTISTAGE=/(?:\b(?:multi[\s-]?stage|multiple\s+build\s+stages?|build\s+stage|scratch\s+image)\b|многоэтапн\w*\s+сборк)/iu;
const DOCKER_LAYERS=/(?:\b(?:image\s+layers?|layered\s+filesystem|read.only\s+layers?|copy.on.write)\b|сло\w*\s+образ|слоист\w*\s+файл)/iu;
const DOCKER_SECURITY=/(?:\b(?:rootless|non.root\s+user|image\s+scanning|least\s+privilege|vulnerabilit(?:y|ies)|supply\s+chain\s+securit)\b|уязвимост\w*\s+образ|безопасност\w*\s+сборк)/iu;
const DOCKER_NETWORK=/(?:\b(?:bridge\s+network|overlay\s+network|host\s+network|port\s+mapping|docker0)\b|сеть\s+docker|сетев\w*\s+режим)/iu;
const DOCKER_STORAGE=/(?:\b(?:bind\s+mount|docker\s+volume|persistent\s+storage)\b|том\w*\s+docker|хранен\w*\s+данн)/iu;
const DOCKER_LIFECYCLE=/(?:\b(?:container\s+lifecycle|docker\s+(?:start|stop|kill)|health\s?check|sigterm|sigkill)\b|жизненн\w*\s+цикл\s+контейнер)/iu;

const DEFAULT_BRIDGE=/(?:\b(?:default\s+bridge|docker0|bridge\s+networks?|bridge\s+mode)\b|стандартн\w*\s+сеть\s+bridge)/iu;
const USER_BRIDGE=/(?:\b(?:user[ -]defined\s+bridge|docker\s+network\s+create|custom\s+bridge|automatic\s+name\s+resolution)\b|пользовательск\w*\s+сеть\s+bridge)/iu;
const HOST_NET=/(?:\b(?:host\s+network|network\s+host|--network\s+host|host\s+mode)\b|сетев\w*\s+режим\s+host)/iu;
const NONE_NET=/(?:\b(?:none\s+network|network\s+none|--network\s+none|network\s+disabled)\b|сетев\w*\s+режим\s+none)/iu;
const OVERLAY_NET=/(?:\b(?:overlay\s+network|overlay\s+mode|across\s+multiple\s+hosts)\b|оверлейн\w*\s+сет)/iu;
const LIFECYCLE_STATES=/(?:\b(?:lifecycle\s+states?|created\s+running\s+stopped|container\s+states?|lifecycle\s+transition)\b|состоян\w*\s+контейнер)/iu;
const SHUTDOWN=/(?:\b(?:docker\s+stop|docker\s+kill|sigterm|sigkill|graceful\s+shutdown)\b|корректн\w*\s+завершен)/iu;
const HEALTH=/(?:\b(?:health\s?check|unhealthy|health\s+status|container\s+health)\b|проверк\w*\s+здоровь)/iu;
const RESTART=/(?:\b(?:restart\s+polic(?:y|ies)|--restart|on.failure\s+restart)\b|политик\w*\s+перезапуск)/iu;
const VOLUMES=/(?:\b(?:docker\s+volumes?|named\s+volume|persistent\s+storage|volumes?\s+persist)\b|именованн\w*\s+том)/iu;
const BIND_MOUNTS=/(?:\b(?:bind\s+mounts?|host\s+directory|tmpfs\s+mount|stateless)\b|монтирован\w*\s+каталог)/iu;
const EPHEMERAL=/(?:\b(?:ephemeral\s+filesystem|container\s+filesystem\s+is\s+ephemeral|temporary\s+filesystem)\b|эфемерн\w*\s+файлов)/iu;
const DAEMON=/(?:\b(?:docker\s+daemon|docker\s+engine|dockerd|containerd|runc|docker\s+cli)\b|демон\s+docker)/iu;
const IMAGE_LAYERS=/(?:\b(?:image\s+layers?|read.only\s+layers?|image\s+model|writable\s+layer)\b|сло\w*\s+образ)/iu;
const CLEAN=/\s+/gu;
const RULES={
 'dockerfile':[
  ['dockerfile-multistage','Многоэтапная сборка образа',MULTISTAGE],
  ['dockerfile-cache','Кеширование слоёв при сборке Dockerfile',BUILDCACHE],
  ['dockerfile-security','Безопасная сборка Docker-образов',DOCKER_SECURITY],
  ['dockerfile-instructions','Инструкции Dockerfile и их назначение',INSTRUCTIONS],
  ['dockerfile-layers','Как формируются слои Docker-образа',DOCKER_LAYERS]
 ],
 'containers-vs-vm':[
  ['virtual-machines','Контейнеры и виртуальные машины',VM],
  ['container-definition','Что такое контейнер',CONTAINER_DEFINITION]
 ],
 'docker-architecture':[
  ['docker-daemon','Docker CLI, daemon и containerd',DAEMON],
  ['docker-image-layers','Слои и модель Docker-образов',IMAGE_LAYERS]
 ],
 'docker-networking':[
  ['network-userbridge','Пользовательская сеть bridge и DNS',USER_BRIDGE],
  ['network-defaultbridge','Стандартная сеть bridge и docker0',DEFAULT_BRIDGE],
  ['network-host','Режим сети host в Docker',HOST_NET],
  ['network-none','Режим сети none в Docker',NONE_NET],
  ['network-overlay','Overlay: сеть Docker между хостами',OVERLAY_NET]
 ],
 'docker-storage':[
  ['storage-ephemeral','Почему файловая система контейнера временная',EPHEMERAL],
  ['storage-volumes','Volumes: постоянное хранение данных Docker',VOLUMES],
  ['storage-bind','Bind mounts и tmpfs',BIND_MOUNTS]
 ],
 'container-lifecycle':[
  ['lifecycle-shutdown','Docker stop и kill: SIGTERM против SIGKILL',SHUTDOWN],
  ['lifecycle-health','Healthcheck и диагностика контейнера',HEALTH],
  ['lifecycle-restart','Политики перезапуска Docker',RESTART],
  ['lifecycle-states','Состояния и переходы контейнера',LIFECYCLE_STATES]
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
/** The slide OCR normally uses key="slide-heading", so derive a chapter
 * category from a source-visible title instead of relying on filename. */
export function resolvedChapterKey(chapter){
 const key=String(chapter?.key||'');
 if(key&&key!=='slide-heading'&&key!=='chapter')return key;
 const label=String(chapter?.title||'');
 if(/dockerfile|докерфайл|production.grade\s+images/iu.test(label))return 'dockerfile';
 if(/container\s+(?:vs\.?|versus)\s+(?:virtual|vm)|контейнер\w*\s+(?:и|против)\s+виртуальн/iu.test(label))return 'containers-vs-vm';
 if(/networking|docker\s+network|сети\s+docker/iu.test(label))return 'docker-networking';
 if(/storage|bind\s+mount|volume|хранение\s+данных/iu.test(label))return 'docker-storage';
 if(/architecture|daemon|containerd|архитектура\s+docker/iu.test(label))return 'docker-architecture';
 if(/lifecycle|health\s?check|жизненный\s+цикл/iu.test(label))return 'container-lifecycle';
 if(/resource\s+(?:isolation|limits)|ограничение\s+ресурсов/iu.test(label))return 'resource-limits';
 return key;
}
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
   return {key:chapter+'-general',title:FALLBACK[chapter]||'Учебная подтема',specific:false,chapter};
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
 return evidence(row?.text,resolvedChapterKey(chapter));
}
export function lessonIdentity(rows,chapter){
 const corpus=(rows||[]).map(r=>String(r?.text||'').replace(CLEAN,' ').trim()).filter(Boolean);
 const key=resolvedChapterKey(chapter);
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
 if(best&&best.specific){
   const span=rows.length?rows.at(-1).end-rows[0].start:0;
   // A single passing mention in eight minutes does not prove eight minutes
   // are exclusively a multi-stage or cache lesson.
   if(key==='dockerfile'&&span>120&&best.hits<2)
     return {key:'dockerfile-general',title:FALLBACK.dockerfile,specific:false,chapter:key};
   return best;
 }
 if(key&&FALLBACK[key])return {key:key==='dockerfile'?'dockerfile-general':key,title:FALLBACK[key],specific:false,chapter:key};
 return best||null;
}
export function distinctVerifiedConcept(a,b){
 if(a.verifiedConcept&&b.verifiedConcept&&
   a.verifiedConcept!==b.verifiedConcept&&
   (a.rows?.length||0)>=3&&(b.rows?.length||0)>=3&&
   a.rows.at(-1).end-a.rows[0].start>=45&&
   b.rows.at(-1).end-b.rows[0].start>=45)return true;
 const left=lessonIdentity(a.rows||[],a.chapter),right=lessonIdentity(b.rows||[],b.chapter);
 return Boolean(left?.specific&&right?.specific&&left.key!==right.key&&
   // Require more than a single incidental mention on both sides
   (a.rows?.length||0)>=2&&(b.rows?.length||0)>=2&&
   (a.rows.at(-1).end-a.rows[0].start)>=30&&
   (b.rows.at(-1).end-b.rows[0].start)>=30);
}
