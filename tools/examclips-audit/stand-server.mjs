import http from 'node:http';
import {createReadStream} from 'node:fs';
import {readFile,lstat} from 'node:fs/promises';
import {join,resolve,extname,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {digest} from './stand-bundle.mjs';
import {assertLocalTarget,publicFailure} from './stand-policy.mjs';

const HERE=dirname(fileURLToPath(import.meta.url));
const CSP="default-src 'self'; script-src 'self' 'wasm-unsafe-eval' blob: https://cdn.jsdelivr.net; worker-src 'self' blob:; connect-src 'self' blob: data: https://huggingface.co https://*.huggingface.co https://*.hf.co https://cdn.jsdelivr.net https://tessdata.projectnaptha.com; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob:; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.wasm':'application/wasm','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'};

export async function startServer(directory,config,{port=5173}={}){
 assertLocalTarget(config.target_url);
 if(config.target_kind!=='test_instance')throw Error('Test instance provenance is required');
 const assets=new Map();
 for(const item of config.assets){
  if(!/^app\/[A-Za-z0-9_./-]+$/.test(item.path)||item.path.split('/').some(piece=>piece==='..'||piece==='.'||!piece))throw Error('Invalid pinned asset path');
  const path=join(directory,item.path),info=await lstat(path);
  if(!info.isFile()||info.isSymbolicLink()||info.size!==item.bytes||await digest(path)!==item.sha256)throw Error('Static app asset integrity mismatch');
  if(assets.has('/'+item.path))throw Error('Duplicate pinned asset');
  assets.set('/'+item.path,{...item,path});
 }
 if(!assets.has('/app/index.html'))throw Error('Static app index is missing');
 const build={targetKind:'test_instance',commit:config.source_commit,sourceRepository:config.source_repository,
  tag:config.source_tag,ciRunId:config.ci_run_id,artifactId:config.artifact_id,artifactSha256:config.artifact_sha256,
  authentication:'not configured in the documented default local build',billing:'not configured',
  servedAssetCount:config.assets.length,assetManifestSha256:createHash('sha256').update(JSON.stringify(config.assets)).digest('hex'),
  assets:config.assets.map(({path,bytes,sha256})=>({path,bytes,sha256})),
  limitations:['Isolated static test instance; does not validate production authentication, billing, hosting or quotas.',
   'The localhost manual OCR selector defaults to auto instead of hosted tesseract. Manual scene analysis is not invoked. Automatic slide OCR defaults to auto in both builds and falls back to browser Tesseract after the unavailable local capability probe.',
   'Public model downloads use their configured runtime locations; unpinned upstream models can change.']};
 const server=http.createServer((request,response)=>{
  // The hosted static app exposes no COEP. Match that runtime so ORT selects
  // the same single-thread WASM path; the pinned app assets remain untouched.
  response.setHeader('Cross-Origin-Opener-Policy','same-origin');
  response.setHeader('Content-Security-Policy',CSP);response.setHeader('X-Content-Type-Options','nosniff');response.setHeader('Cache-Control','no-store');
  const send=(status,body,type='application/json; charset=utf-8')=>{response.writeHead(status,{'Content-Type':type,'Content-Length':Buffer.byteLength(body)});response.end(request.method==='HEAD'?undefined:body)};
  if(request.headers.host!=='127.0.0.1:'+server.address().port)return send(421,'{"error":"Unexpected host"}');
  if(!['GET','HEAD'].includes(request.method))return send(405,'{"error":"Read only"}');
  const raw=request.url||'';
  if(!raw.startsWith('/')||raw.startsWith('//')||/[\\%\x00-\x1f]/.test(raw)||raw.split(/[/?]/).some(piece=>piece==='..'||piece==='.'))return send(400,'{"error":"Invalid path"}');
  const path=raw.split('?')[0];
  if(path==='/site-build.json')return send(200,JSON.stringify(build));
  if(path==='/healthz')return send(200,'{"targetKind":"test_instance","ready":true}');
  const asset=assets.get(path==='/app/'||path==='/app'?'/app/index.html':path);
  if(!asset)return send(404,'{"error":"Static asset not found"}');
  response.writeHead(200,{'Content-Type':MIME[extname(asset.path)]||'application/octet-stream','Content-Length':asset.bytes});
  if(request.method==='HEAD')return response.end();
  const file=createReadStream(asset.path);file.on('error',()=>response.destroy());file.pipe(response);
 });
 await new Promise((yes,no)=>{server.once('error',no);server.listen(port,'127.0.0.1',()=>{server.off('error',no);yes()})});
 return server;
}

async function main(){
 if(!process.env.AUDIT_ROOT)throw Error('Private audit root is required');
 const config=JSON.parse(await readFile(join(HERE,'stand-config.json'),'utf8'));
 const server=await startServer(join(resolve(process.env.AUDIT_ROOT),'site'),config);
 console.log('STAND_SERVER_READY '+JSON.stringify({targetKind:'test_instance',target:config.target_url,sourceCommit:config.source_commit,artifactId:config.artifact_id}));
 for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>server.close(()=>process.exit(0)));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error(publicFailure());process.exitCode=1});
