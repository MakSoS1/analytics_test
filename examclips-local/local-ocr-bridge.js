/**
 * Strict opt-in RapidOCR bridge (Vite dev/preview ONLY).
 * No uploading to external services. Python is a fixed, local script; argv is not user supplied.
 * It receives base64 encoded PNG on STDIN, then returns bounded text boxes.
 */
import {spawn} from 'node:child_process';
import {existsSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const base=join(fileURLToPath(new URL('.',import.meta.url)));
const pathToWorker=join(base,'scripts','rapidocr_local.py');
const localPython=process.env.EXAMCLIPS_OCR_PYTHON ||
  (process.platform==='win32'?join(base,'.ocr-venv','Scripts','python.exe'):join(base,'.ocr-venv','bin','python'));
const atLocalhost=ip=>ip==='127.0.0.1'||ip==='::1'||ip==='::ffff:127.0.0.1';
export function validatePngRequest(data){
 if(!data||!['en','ru'].includes(data.language))throw Error('Language must be en or ru');
 if(typeof data.png_base64!=='string'||data.png_base64.length>4_700_000)throw Error('Invalid image size');
 if(!/^[A-Za-z0-9+/]+={0,2}$/.test(data.png_base64))throw Error('Invalid base64 PNG data');
 const header=Buffer.from(data.png_base64.slice(0,16),'base64');
 if(!header.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))
  throw Error('Not a PNG');
 return {language:data.language,png_base64:data.png_base64};
}
export function runPrivateOcr(input,python=localPython,{timeout=90000}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn(python,[pathToWorker],{
   cwd:base,windowsHide:true,shell:false,stdio:['pipe','pipe','pipe'],env:{...process.env,PYTHONIOENCODING:'utf-8'}
  });
  const timer=setTimeout(()=>child.kill(),timeout);
  let stdout='',stderr='',length=0;
  child.stdout.on('data',buf=>{length+=buf.length;
    if(length>600000){child.kill();reject(Error('OCR response too large'));return}
    stdout+=buf.toString('utf8');
  });
  child.stderr.on('data',buf=>{if(stderr.length<1200)stderr+=buf.toString('utf8')});
  child.on('error',err=>{clearTimeout(timer);reject(err)});
  child.on('close',code=>{
    clearTimeout(timer);
    if(code!==0)return reject(Error('Local PP-OCR failed: '+stderr.slice(-250)));
    try{
      const data=JSON.parse(stdout.trim());
      if(!Array.isArray(data.lines)||data.lines.length>800)throw Error('Invalid OCR response');
      resolve(data);
    }catch(err){reject(err)}
  });
  child.stdin.on('error',()=>{});
  child.stdin.end(JSON.stringify(input));
 });
}
async function readBounded(req,limit=4800000){
 let data='',size=0;
 for await(const chunk of req){
   size+=chunk.byteLength;
   if(size>limit)throw Error('Request too large');
   data+=chunk.toString('utf8');
 }
 return JSON.parse(data);
}
function respond(res,status,obj){
 res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 res.end(JSON.stringify(obj));
}
export function rapidOcrBridge(){
 let availability=null,lastProbe=0;
 const middleware=(server)=>{
  server.middlewares.use(async(req,res,next)=>{
   if(!req.url?.startsWith('/api/local-ocr'))return next();
   if(!atLocalhost(req.socket.remoteAddress))
     return respond(res,403,{error:'OCR доступен только на этом компьютере'});
   if(req.headers.origin&&req.headers.origin!=='http://'+req.headers.host)
     return respond(res,403,{error:'Cross-origin image data blocked'});
   if(req.url==='/api/local-ocr-capabilities'&&req.method==='GET'){
     // This probe cannot install or download models.
     if(Date.now()-lastProbe>15000){
       lastProbe=Date.now();availability=existsSync(localPython);
     }
     return respond(res,200,{available:availability,engine:'PP-OCRv6 small (EN) / PP-OCRv5 mobile (RU)',
       installRequired:!availability,localOnly:true});
   }
   if(req.url==='/api/local-ocr'&&req.method==='POST'){
     if(!existsSync(localPython))return respond(res,503,{error:'RapidOCR не установлен. Выберите Tesseract.js или запустите установщик локального OCR.'});
     if(!String(req.headers['content-type']||'').startsWith('application/json'))
       return respond(res,415,{error:'JSON required'});
     try{
       const input=validatePngRequest(await readBounded(req));
       const result=await runPrivateOcr(input);
       return respond(res,200,result);
     }catch(e){return respond(res,503,{error:String(e.message||e).slice(0,350)})}
   }
   return respond(res,404,{error:'Unknown local OCR endpoint'});
  });
 };
 return {name:'examclips-optional-local-rapidocr',configureServer:middleware,configurePreviewServer:middleware};
}
