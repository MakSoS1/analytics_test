import {defineConfig} from 'vite';
import {normalizeReview,prepareReviewRequest,reviewPrompt} from './src/completion-review.js';
// A strictly loopback-only Ollama bridge for local Vite launches.
// No endpoints forward video, audio, stills or full lecture files.
// Production static builds have no bridge: the browser fallback remains available.
const OLLAMA='http://127.0.0.1:11434';
const allowedAddress=ip=>ip==='127.0.0.1'||ip==='::1'||ip==='::ffff:127.0.0.1';
const fail=(response,status,message)=>{
 response.statusCode=status;response.setHeader('Content-Type','application/json; charset=utf-8');
 response.setHeader('Cache-Control','no-store');
 response.end(JSON.stringify({error:message}));
};
const reply=(response,data)=>{
 response.statusCode=200;response.setHeader('Content-Type','application/json; charset=utf-8');
 response.setHeader('Cache-Control','no-store');
 response.end(JSON.stringify(data));
};
async function installedModels(){
 const response=await fetch(OLLAMA+'/api/tags',{signal:AbortSignal.timeout(3500)});
 if(!response.ok)throw Error('Ollama недоступна на этом компьютере');
 const data=await response.json();
 return (data.models||[]).map(x=>x.name).filter(x=>typeof x==='string').slice(0,100);
}
async function readJsonRequest(req){
 let data='',size=0;
 for await(const buf of req){
   size+=buf.length;if(size>48000)throw Error('Слишком большой запрос — выберите одну микротему');
   data+=buf.toString('utf8');
 }
 try{return JSON.parse(data)}catch{throw Error('Некорректный JSON')}
}
function localOllamaBridge(){
 const register=(server)=>{
  server.middlewares.use(async(req,res,next)=>{
    if(!req.url?.startsWith('/api/local-review'))return next();
    if(!allowedAddress(req.socket.remoteAddress))return fail(res,403,'Доступ только с текущего компьютера');
    if(req.headers.origin&&req.headers.origin!=='http://'+req.headers.host)
      return fail(res,403,'Недопустимый Origin — локальная проверка защищена');
    try{
      if(req.url==='/api/local-review-capabilities'&&req.method==='GET'){
        let models=[];try{models=await installedModels()}catch{}
        return reply(res,{available:models.length>0,model:models.find(x=>/qwen/i.test(x))||models[0]||null,
          note:'Модели используются только в Ollama на 127.0.0.1. Новые веса не скачиваются.'});
      }
      if(req.url==='/api/local-review'&&req.method==='POST'){
        if(!(req.headers['content-type']||'').startsWith('application/json'))
          return fail(res,415,'Ожидается application/json');
        const models=await installedModels();
        const model=models.find(x=>/qwen/i.test(x))||models[0];
        if(!model)return fail(res,503,'Нет установленных локальных моделей Ollama');
        const payload=await readJsonRequest(req);
        prepareReviewRequest(payload);
        const result=await fetch(OLLAMA+'/api/generate',{
          method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({model,prompt:reviewPrompt(payload),stream:false,format:'json',
            options:{temperature:0,num_predict:600,num_ctx:8192},keep_alive:'2m'}),
          signal:AbortSignal.timeout(180000)
        });
        if(!result.ok)throw Error('Локальная Ollama вернула код '+result.status);
        const response=await result.json();
        let parsed;try{parsed=JSON.parse(response.response)}catch{
          throw Error('Модель вернула невалидный JSON. Границы не изменены')}
        return reply(res,normalizeReview({...parsed,model},payload));
      }
      return fail(res,404,'Локальный маршрут не найден');
    }catch(error){
      const timeout=error.name==='TimeoutError';
      return fail(res,timeout?504:503,timeout?'Локальная LLM не ответила вовремя':String(error.message).slice(0,190));
    }
  });
 };
 return {name:'examclips-local-ollama-bridge',configureServer:register,configurePreviewServer:register};
}
export default defineConfig({
 server:{host:'127.0.0.1',strictPort:false},
 preview:{host:'127.0.0.1'},
 plugins:[localOllamaBridge()]
});
