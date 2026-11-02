import test from 'node:test';import assert from 'node:assert/strict';
import {quizForClip,gradeQuiz,toQuizJson} from '../src/quiz.js';
const lecture=[
 {start:0,end:28,text:'Контейнеры применяются для изоляции различных приложений и библиотек. Образы позволяют повторять настройки системного окружения.'},
 {start:28,end:55,text:'Виртуальная машина использует отдельное ядро операционной системы. Контейнер Docker разделяет ресурсы между различными процессами.'},
 {start:55,end:85,text:'Оркестрация управляет распределением контейнеров между вычислительными узлами. Конфигурация указывается разработчиком в декларативных файлах.'},
 {start:85,end:110,text:'Мониторинг показывает состояние служб и сетевого интерфейса. Приложение обращается к контейнерам через виртуальную сеть.'}
];
test('quiz never invents answer, all responses are literal lesson speech',()=>{
 const q=quizForClip({start:0,end:120,title:'Контейнеры'},lecture);
 assert.ok(q.length>=3);
 for(const x of q){assert.ok(x.evidence.includes(x.reference));assert.equal(x.options[x.correctIndex],x.reference);assert.equal(x.options.length,4);}
});
test('insufficient ASR yields zero questions instead of fake test',()=>{
 assert.deepEqual(quizForClip({start:0,end:8},[{start:0,end:8,text:'Docker'}]),[]);
});
test('quiz scoring uses known choice indices, no outside analytics',()=>{
 const questions=quizForClip({start:0,end:120},lecture);
 const exact=questions.map(q=>q.correctIndex);
 const result=gradeQuiz(questions,exact);
 assert.equal(result.correct,questions.length);assert.equal(result.percent,100);
 assert.equal(gradeQuiz(questions,[]).correct,0);
});
test('export includes exact evidence and no ungrounded educational promises',()=>{
 const clip={start:0,end:110,title:'Контейнеры'};
 const questions=quizForClip(clip,lecture);
 assert.equal(toQuizJson(clip,questions).questions.length,questions.length);
 assert.match(toQuizJson(clip,questions).disclaimer,/not an independently validated/i);
});
