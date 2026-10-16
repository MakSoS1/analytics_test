import {createServer} from 'node:http';
import assert from 'node:assert/strict';
const model='qwen-local-test:0.1',origin=process.env.EXAMCLIPS_ORIGIN||'http://127.0.0.1:5173';
let seen=0;
const server=createServer(async(req,res)=>{
 let body='';for await(const p of req)body+=p.toString('utf8');
 res.setHeader('Content-Type','application/json');
 if(req.url==='/api/tags'){
   res.end(JSON.stringify({models:[{name:model}]}));return
 }
 if(req.url==='/api/generate'){
   seen++;
   const request=JSON.parse(body);
   assert.equal(request.model,model);
   assert.equal(request.stream,false);
   assert.match(request.prompt,/Docker позволяет изолировать приложения/);
   if(request.prompt.includes('SELECT_HIGHLIGHTS')){
     res.end(JSON.stringify({response:JSON.stringify({
       stories:[{ids:['candidate-1','candidate-2'],
         evidence:['Docker позволяет изолировать приложения в контейнерах',
           'Контейнеры используют образы и запускаются'],
         reason:'Объяснение контейнеров'}]
     })}));return
   }
   assert.ok(!request.prompt.includes('data:video'));
   res.end(JSON.stringify({response:JSON.stringify({
     verdict:'complete',confidence:.8,
     evidence:['Docker позволяет изолировать приложения в контейнерах.'],
     explanation:'Тема объясняется от определения до вывода',suggestedStartDelta:0,suggestedEndDelta:0
   })}));return
 }
 res.statusCode=404;res.end('{}');
});
await new Promise((resolve,reject)=>server.once('error',reject).listen(11434,'127.0.0.1',resolve));
const payload={clip:{start:0,end:80,title:'Docker',duration:80},before:[],
 inside:[{start:0,end:40,text:'Docker позволяет изолировать приложения в контейнерах.'},
 {start:40,end:80,text:'Контейнеры используют образы и запускаются в повторяемом окружении.'}],
 after:[{start:81,end:96,text:'Следующая тема — виртуальные сети Docker.'}]};
try{
 const cap=await fetch(origin+'/api/local-review-capabilities');
 assert.equal(cap.status,200);
 const available=await cap.json();
 assert.equal(available.available,true);
 assert.equal(available.model,model);
 const bad=await fetch(origin+'/api/local-review',{method:'POST',headers:{
   'Content-Type':'application/json','Origin':'https://outside.example'},
   body:JSON.stringify(payload)});
 assert.equal(bad.status,403);
 const response=await fetch(origin+'/api/local-review',{method:'POST',headers:{
   'Content-Type':'application/json','Origin':origin},body:JSON.stringify(payload)});
 assert.equal(response.status,200);
 const result=await response.json();
 assert.equal(result.verdict,'complete');assert.equal(result.evidenceVerified,true);
 const storyPayload={duration:480,keepFraction:.3,sections:[
   {id:'candidate-1',start:10,end:42,text:'Docker позволяет изолировать приложения в контейнерах.'},
   {id:'candidate-2',start:230,end:271,text:'Контейнеры используют образы и запускаются в повторяемом окружении.'}
 ]};
 const storyResponse=await fetch(origin+'/api/local-story-plan',{method:'POST',headers:{
   'Content-Type':'application/json','Origin':origin},body:JSON.stringify(storyPayload)});
 assert.equal(storyResponse.status,200);
 const selected=await storyResponse.json();
 assert.equal(selected.clips.length,1);
 assert.equal(selected.clips[0].segments.length,2);
 assert.equal(selected.clips[0].status,'needs-review');
 assert.equal(seen,2);
 console.log('LOCAL_LLM_STORY_SELECTOR_SUCCESS',selected.summary.keptPercent,'two verified nonadjacent evidence excerpts');
 console.log('LOCAL_LLM_VERIFIER_SUCCESS',result.verdict,result.confidence,'no remote model or lecture upload');
}finally{await new Promise(resolve=>server.close(resolve))}
