/**
 * Discourse roles of spoken lecture sentences. Subject-independent: these are
 * how lecturers open, close, pause for questions and plan, not what they teach.
 */
const LEAD=String.raw`^\s*(?:(?:okay|ok|oh|well|so|and|but|now|alright|right|итак|хорошо|ну|так|но)[,.!]?\s+)*`;
const STRONG=new RegExp(LEAD+String.raw`(?:`+[
 String.raw`now[, ]+(?:let(?:'s| us)\s+)?(?:talk|discuss|look at|consider|move|turn|speak|go)`,
 String.raw`now[, ]+before\s+we\s+(?:compare|go|move|look)`,
 String.raw`(?:now[, ]+)?the other half of`,
 String.raw`let(?:'s| us)\s+(?:talk|discuss|move|turn|speak|tackle|dig into|dive into|get back to|go to)`,
 String.raw`(?:and\s+)?now\s+we(?:'re| are)?\s+(?:going\s+)?to\s+talk`,
 String.raw`now,?\s+a quick (?:but )?(?:important )?(?:clarification|note|word)`,
 String.raw`we(?:'ll| will| are going to)\s+(?:now\s+)?(?:speak|talk) about`,
 String.raw`(?:the\s+)?next\s+(?:topic|question|concept|objective|principle|point|part|section)`,
 String.raw`(?:our|the)\s+(?:first|second|third|fourth|fifth|next|final|last)\s+(?:design\s+)?(?:objective|principle|topic|concept|pillar|section|part)`,
 String.raw`(?:and\s+)?finally,?\s+we\s+(?:are\s+)?arriv`,
 String.raw`(?:so,?\s+)?(?:and\s+)?we\s+(?:also\s+)?have\s+(?:a|one|another)\s+(?:fundamental|key|core|important|basic)\s+(?:principle|concept|idea|pattern|rule)`,
 String.raw`(?:and\s+)?now\s+we\s+(?:arrive|come|get)\s+(?:at|to)`,
 String.raw`moving on`,
 String.raw`here(?:'s| is) the (?:truth|problem|question)`,
 String.raw`let me leave you with`,
 String.raw`теперь\s+(?:рассмотрим|поговорим|обсудим|перейд[её]м)`,
 String.raw`перейд[её]м\s+к`,
 String.raw`следующ(?:ая|ий|ее)\s+(?:тема|вопрос|понятие|принцип)`
].join('|')+')','iu');
// "And we also have idempotency." / "Next one is host." / "So next the SLO." / "And security."
const NAMED=new RegExp(LEAD+String.raw`(?:(?:(?:and\s+)?we\s+also\s+have|(?:the\s+)?next\s+(?:one\s+)?is|next,?\s+the|it'?s called|(?:and\s+)?finally,?\s+(?:the\s+|for\s+)?)\s*[\p{L}][\p{L}\s,-]{1,60}[.!]?$)`,'iu');
// "Let's start with ..." also opens sub-steps inside a topic: medium evidence.
const MEDIUM=new RegExp(LEAD+String.raw`(?:let(?:'s| us)\s+(?:start|begin)|so,? let'?s begin|to bring (?:all )?(?:of )?(?:this|it|that)\b.{0,40}\bto life|let'?s see (?:how )?(?:it|this) (?:works )?in practice|на практике (?:это|мы))`,'iu');
const ORDINAL=new RegExp(LEAD+String.raw`(?:first|second|third|fourth|fifth|finally|во-первых|во-вторых|в-третьих)[,]?\s+(?:is\s+|it'?s\s+|its\s+|we\s+have\s+)?`,'iu');
const CLOSING=new RegExp(LEAD+String.raw`(?:in summary|to summarize|to sum up|so here(?:'s| is) (?:a|the) full picture|so,? that'?s [\p{L}]+\.?$|that'?s (?:it|all) (?:for|about)|подвед[её]м итог|подводя итог|таким образом,? (?:мы|итог))`,'iu');
// Pauses for questions; they end a section and may open a Q&A exchange.
const INVITE=/(?:\bdo you (?:still )?have (?:any |more |some )?questions?\b|\bany (?:more |other )?questions\b|\bquestions? in (?:the )?chat\b|(?:i(?:'ll| will)|let me) (?:check|read) (?:the )?chat|let'?s see,? (?:the )?chat|есть (?:ли )?(?:ещё )?вопросы|вопросы есть)/iu;
// Spoken transitions without content: dropped from the video, kept as boundary evidence.
const MOVE_ON=/^(?:\s*(?:okay|ok|so|and|well)[,.]?\s+)*(?:let'?s (?:move|go) (?:on|next|to the next (?:part|point))|let'?s go next|we(?:'ll| will) go next|let'?s move on)/iu;
export const movesOn=text=>MOVE_ON.test(String(text||''));
const FILLER=/(?:please,? write (?:them |it )?(?:in|to) (?:the )?chat|(?:write|make some) (?:responses? )?in (?:the )?chat|say (?:it )?by your voice|make some reactions|thumbs? (?:up|down)|(?:so,? )?no questions?\b|still no questions|nothing in (?:the )?chat|don'?t have anything in (?:the )?chat|you don'?t have to wait for my asking|i(?:'ll| will) read (?:the )?chat later|(?:next|on the next) q ?&? ?a session|okay,? let'?s (?:move|go) (?:on|next|to the next (?:part|point))\.?$|let'?s go next\.?$|we(?:'ll| will) go next\.?$|let'?s get started\.?$|sounds good\??$|напишите в чат|вопросов нет|поехали дальше)/iu;
const LOGISTICS=/(?:minutes? break|hour break|have a break|put the thumb up|lab part|practical part|in eight minutes|перерыв|практическ\S* част)/iu;
const ASKED=/(?:\bsome chat message|\bquestion in (?:the )?chat\b|\bi have a question\b|\b(?:one |a )?(?:small |quick )?question about\b|\bactually,? yes\b|вопрос из чата|в чате спрашивают|у меня вопрос)/iu;
const THANKS=/(?:thank you for (?:a |the |your )?(?:great |good )?question|that'?s cool,? thanks|^\s*okay,? thank you\.?$|thank you for your time|спасибо за вопрос)/iu;
const WELCOME=/^(?:\s*(?:well|okay|so)[,.]?\s+)*(?:let'?s start(?: it)?\.?$|good (?:morning|afternoon|evening)|hello|hi everyone|welcome|добрый (?:день|вечер)|здравствуйте|всем привет)/iu;
const BIO=/(?:my name is|the only one thing i can say|i'?ve (?:built|designed|worked)|i'?ll be your guide|i'?ve spent the last|years building|one of my favou?rite projects|i also took part|i'?ve been in the trenches|меня зовут|я работаю|мой опыт)/iu;
const AGENDA=/(?:let me give you a (?:quick )?(?:map|roadmap)|what (?:exactly )?are we covering|roadmap of what we'?ll|by the end of this (?:lecture|week'?s lab)|^\s*(?:(?:well|and|so)[,]?\s+)*(?:first|second|third|fourth|fifth|then|from there|also|and finally|finally)[,]?\s+(?:we(?:'ll| will| can)|the main event|now we'?ll)|^\s*we'?ll start with|сегодня (?:мы )?(?:поговорим|рассмотрим|разберём)|план (?:лекции|занятия))/iu;
const RECAP=/(?:takeaways|let'?s summari[sz]e|so let'?s summari|we arrive at the end of the lecture|we learned that|what we'?ve spoken today|подвед[её]м итоги|итоги лекции)/iu;

export const opener=text=>{
 const s=String(text||'');
 if(/^\s*(?:(?:okay|ok|good|great|yes|no|right|well|so|sure|thanks|exactly|really|correct|fine|good evening|хорошо|да|нет|отлично|ну|итак)[,.!?]?\s*)+$/iu.test(s))return 0;
 // "We'll speak about this later" points forward; it does not open a topic.
 if(/\blater\b|next (?:lecture|time|week)|at the end of the course|позже|в следующий раз/iu.test(s))return 0;
 if(STRONG.test(s))return 3.2;
 // A one-word heading ("And security.") is a stronger cue than a named list item.
 if(MEDIUM.test(s))return 2.2;
 // A spoken one-word heading needs a connective: "And security." ("Copy." is ASR noise).
 if(/^\s*(?:and|now|next)[,]?\s+[\p{L}-]+[.!]$/iu.test(s)&&!/^\s*(?:and|now|next)[,]?\s+(?:okay|ok|so|yes|no|then|again|here|there|that|this|it)[.!]$/iu.test(s))return 2.8;
 if(NAMED.test(s)&&s.split(/\s+/u).length<=8)return 2.2;
 if(ORDINAL.test(s))return 1.6;
 return 0;
};
export const closes=text=>CLOSING.test(String(text||''));
export const invitesQuestions=text=>INVITE.test(String(text||''));
export const isFiller=text=>FILLER.test(String(text||''))||LOGISTICS.test(String(text||''));
export const reportsQuestion=text=>ASKED.test(String(text||''));
export const thanksForQuestion=text=>THANKS.test(String(text||''));
export const isRecap=text=>RECAP.test(String(text||''));
/** Welcome, biography and lecture plan: valid only in the opening of a lecture. */
export const isOpeningHousekeeping=text=>{const s=String(text||'');return WELCOME.test(s)||BIO.test(s)||AGENDA.test(s)};
