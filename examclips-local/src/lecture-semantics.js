/**
 * Extractive lecture-topic vocabulary and concise evidence-grounded headings.
 * A topic label is suggested only when its terms are present in ASR/SRT.
 * Not a substitute for semantic segmentation or a verified transcript.
 */
const RULES=[
 {key:'virtual-machines',title:'Контейнеры и виртуальные машины',pattern:/\b(?:virtual\s+machines?|vms?|hypervisor|виртуальн\w*\s+машин|гипервизор)\b/iu,weight:3},
 {key:'dockerfile',title:'Dockerfile и сборка образа',pattern:/\b(?:dockerfile|multi[ -]?stage|build\s+context|docker\s+build|докерфайл|многоэтапн\w*\s+сборк)\b/iu,weight:4},
 {key:'docker-networking',title:'Сети Docker: bridge и overlay',pattern:/\b(?:network(?:ing|s)?|bridge|overlay|docker0|port\s+mapping|маршрутизац\w*|сет\w*\s+docker)\b/iu,weight:3},
 {key:'container-lifecycle',title:'Жизненный цикл и здоровье контейнера',pattern:/\b(?:lifecycle|healthchecks?|health\s+check|docker\s+(?:stop|kill|pause|start)|sigterm|жизненн\w*\s+цикл|провер\w*\s+здоровь)\b/iu,weight:4},
 {key:'docker-images',title:'Образы и слои Docker',pattern:/\b(?:images?|image\s+layers?|docker\s+pull|docker\s+push|registry|docker\s+hub|образ\w*|сло\w*\s+образ\w*)\b/iu,weight:2},
 {key:'docker-architecture',title:'Архитектура Docker',pattern:/\b(?:architecture|daemon|docker\s+engine|containerd|runc|архитектур\w*|движок\s+docker)\b/iu,weight:3},
 {key:'docker-storage',title:'Тома и хранение данных Docker',pattern:/\b(?:volumes?|mounts?|persistent\s+storage|bind\s+mount|том\w*\s+docker|хранени\w*\s+данных)\b/iu,weight:3},
 {key:'docker-commands',title:'Команды Docker CLI',pattern:/\b(?:docker\s+(?:run|exec|ps|logs|inspect|rm|system|compose)|docker\s+cli|команд\w*\s+docker)\b/iu,weight:3},
 {key:'kubernetes',title:'Основы Kubernetes',pattern:/\b(?:kubernetes|kubectl|кubernetes|кубернетес)\b/iu,weight:3},
 {key:'docker-containers',title:'Что такое контейнер Docker',pattern:/\b(?:containers?|контейнер\w*|docker)\b/iu,weight:1},
 {key:'equations',title:'Разбор уравнения',pattern:/\b(?:уравнен\w*|equation)\b/iu,weight:2},
 {key:'algorithms',title:'Разбор алгоритма',pattern:/\b(?:алгоритм\w*|algorithm)\b/iu,weight:2}
];
const NOISE=/\b(?:lecture|about me|welcome|agenda|brief|today|привет|лекц\w*|заняти\w*|тема|сегодня)\b/giu;
const WORDS=/[\p{L}\p{N}][\p{L}\p{N}-]*/gu;
const TEACHING_SIGNAL=/(?:\bbecause\b|\bmeans\b|\bwhich\b|\bfor example\b|\bso that\b|\ballows?\b|\bcontain(?:s|ers?)\b|\bis (?:a |an |the )?\b|потому что|например|это\s+|позволя\w*|означа\w*|устроен\w*)/iu;
const AGENDA=/(?:\b(?:lecture\s*(?:1|one)\s*(?:brief|overview|agenda)|agenda|course\s+outline|about\s+me|introduction\s+to\s+(?:the\s+)?course|we(?:'ll|\s+will)\s+(?:cover|discuss|talk\s+about)|today\s+we(?:'ll|\s+will)\s+(?:look at|explore|learn)|this\s+lecture\s+(?:covers|is about)|\bwhat\s+we\s+will\s+(?:cover|learn))|\b(?:сегодня\s+(?:мы\s+)?(?:рассмотрим|поговорим|изучим)|план\s+(?:лекции|занятия)|на\s+этой\s+лекции\s+мы\s+будем))/iu;
const BIO=/(?:\babout\s+me\b|\b(?:i\s+(?:am|work|have|used\s+to)|my\s+(?:name|background|experience|career)|\d{1,2}\+?\s+years?\s+(?:of\s+)?(?:experience|development)|years?\s+(?:in|of)\s+(?:software|development|industry)|i(?:'ve|\s+have)\s+been\s+(?:working|developing))\b|\b(?:меня\s+зовут|мой\s+опыт|мой\s+стаж|я\s+(?:работаю|преподаю)|немного\s+о\s+себе|доцент\s+кафедры)\b)/iu;
const LOGISTICS=/(?:\b(?:microphone|sound\s+check|can\s+you\s+hear|course\s+schedule|grading|semester|homework\s+deadline|attendance|office\s+hours|let\s+me\s+share\s+my\s+screen)\b|(?:расписани\w*|проверка\s+микрофона|как\s+будет\s+проходить\s+курс|организационн\w*\s+момент))/iu;
const ENUM=/(?:,|;|\/|\b(?:and|or)\b|\b(?:и|или)\b)/giu;
/**
 * Remove clearly introductory biography/outline rows; never reject an
 * evidenced technical explanation just because it begins with "today".
 */
export function isLectureHousekeeping(text){
 const s=String(text||'').trim();
 if(!s)return true;
 if(LOGISTICS.test(s)&&!TEACHING_SIGNAL.test(s))return true;
 if(BIO.test(s)&&!/(?:for example|например|means|то есть|потому что)/iu.test(s))return true;
 if(AGENDA.test(s)){
   const teaching=TEACHING_SIGNAL.test(s);
   // "what is container, Dockerfile, lifecycle" is a list, not an answer.
   const listing=(s.match(ENUM)||[]).length>=2;
   if(!teaching||listing)return true;
 }
 return false;
}
export function topicEvidence(text){
 const s=String(text||'');
 const matching=RULES.filter(r=>r.pattern.test(s));
 if(!matching.length)return null;
 const chosen=matching.sort((a,b)=>b.weight-a.weight)[0];
 return {key:chosen.key,title:chosen.title,weight:chosen.weight,
   keys:matching.map(x=>x.key)};
}
export function meaningfulTitle(rows){
 const corpus=(rows||[]).map(r=>String(r.text||r)).filter(Boolean);
 const relevant=corpus.filter(s=>!isLectureHousekeeping(s));
 const weighted=new Map();
 for(const s of relevant){
   const ev=topicEvidence(s);
   if(ev){const x=weighted.get(ev.key)||{score:0,title:ev.title};x.score+=ev.weight;weighted.set(ev.key,x)}
 }
 const top=[...weighted].sort((a,b)=>b[1].score-a[1].score)[0];
 if(top)return top[1].title;
 const sentence=(relevant[0]||corpus[0]||'').replace(NOISE,'').trim().replace(/^[—:.,\s]+/u,'');
 const words=sentence.match(WORDS)||[];
 const title=words.slice(0,7).join(' ').replace(/[.,:;!?]+$/u,'');
 return title?title.charAt(0).toUpperCase()+title.slice(1):'Микротема без названия — проверьте';
}
export function topicChangeEvidence(previous,next){
 const a=topicEvidence(previous),b=topicEvidence(next);
 if(!a||!b||a.key===b.key)return null;
 if(a.key==='docker-containers'||b.key==='docker-containers')return null;
 return {from:a.key,to:b.key,confidence:b.weight>=3?'moderate':'low'};
}
