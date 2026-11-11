import {readFile,writeFile,stat} from 'node:fs/promises';
import {seal,keyHash} from './crypto.mjs';
import {handoffLayout} from './audit-context.mjs';

const [publicFile,credentialFile,outputFile]=process.argv.slice(2);
if(!publicFile||!credentialFile||!outputFile)throw Error('Usage: node encrypt-handoff.mjs PUBLIC_JSON PRIVATE_CREDENTIALS_JSON OUTPUT_JSON');
const descriptor=JSON.parse(await readFile(publicFile,'utf8'));
if(Date.parse(descriptor.expiresAt)<=Date.now())throw Error('Handoff public key has expired');
if(descriptor.context?.purpose!=='credentials'||descriptor.context.repository!=='MakSoS1/analytics_test'||
  descriptor.context.branch!=='qa/examclips-audit-2026-11-11')throw Error('Unexpected handoff destination');
handoffLayout(descriptor.context);
if(keyHash(descriptor.publicKeyPem)!==descriptor.keySha256)throw Error('Public key fingerprint mismatch');
if((await stat(credentialFile)).mode&0o077)throw Error('Credential input file must have mode 600 or stricter');
const credentials=JSON.parse(await readFile(credentialFile,'utf8'));
if(typeof credentials.email!=='string'||typeof credentials.password!=='string')throw Error('Expected email and password');
const bytes=Buffer.from(JSON.stringify({email:credentials.email,password:credentials.password}));
const envelope=seal(bytes,descriptor.publicKeyPem,descriptor.context);bytes.fill(0);
await writeFile(outputFile,JSON.stringify(envelope,null,2)+'\n',{mode:0o600});
console.log('Encrypted credential envelope written for run '+descriptor.context.runId+' attempt '+descriptor.context.runAttempt+' case '+descriptor.context.caseId);
