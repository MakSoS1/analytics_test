import {createCipheriv,createDecipheriv,publicEncrypt,privateDecrypt,randomBytes,createHash,constants} from 'node:crypto';
import {createReadStream,createWriteStream} from 'node:fs';
import {rm} from 'node:fs/promises';
import {pipeline} from 'node:stream/promises';

export const algorithm='AES-256-GCM+RSA-OAEP-SHA256';
export const keyHash=pem=>createHash('sha256').update(pem.trim()).digest('hex');
const canonical=value=>JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))));
function header(publicKey,context) {
  return {version:1,algorithm,keySha256:keyHash(publicKey),context};
}
function check(envelope,context) {
  if(envelope?.version!==1||envelope.algorithm!==algorithm)throw Error('Unsupported encrypted envelope');
  if(canonical(envelope.context||{})!==canonical(context))throw Error('Envelope context does not match this run');
  if(Buffer.from(envelope.iv||'','base64').length!==12||Buffer.from(envelope.tag||'','base64').length!==16)
    throw Error('Invalid encrypted envelope');
}
function encryptor(publicKey,context) {
  const key=randomBytes(32),iv=randomBytes(12),meta=header(publicKey,context);
  const cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from(canonical(meta)));
  meta.wrappedKey=publicEncrypt({key:publicKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},key).toString('base64');
  meta.iv=iv.toString('base64');
  key.fill(0);
  return {meta,cipher};
}
function decryptor(envelope,privateKey,context) {
  check(envelope,context);
  const key=privateDecrypt({key:privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},Buffer.from(envelope.wrappedKey,'base64'));
  const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(envelope.iv,'base64'));
  decipher.setAAD(Buffer.from(canonical({version:envelope.version,algorithm:envelope.algorithm,keySha256:envelope.keySha256,context:envelope.context})));
  decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));key.fill(0);
  return decipher;
}
export function seal(bytes,publicKey,context) {
  const {meta,cipher}=encryptor(publicKey,context);
  const encrypted=Buffer.concat([cipher.update(bytes),cipher.final()]);
  return {...meta,tag:cipher.getAuthTag().toString('base64'),ciphertext:encrypted.toString('base64')};
}
export function open(envelope,privateKey,context) {
  const decipher=decryptor(envelope,privateKey,context);
  return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64')),decipher.final()]);
}
export async function sealFile(source,destination,publicKey,context) {
  const {meta,cipher}=encryptor(publicKey,context);
  await pipeline(createReadStream(source),cipher,createWriteStream(destination,{mode:0o600}));
  return {...meta,tag:cipher.getAuthTag().toString('base64')};
}
export async function openFile(source,destination,envelope,privateKey,context) {
  try {
    const decipher=decryptor(envelope,privateKey,context);
    await pipeline(createReadStream(source),decipher,createWriteStream(destination,{mode:0o600}));
  } catch(error) {await rm(destination,{force:true});throw error;}
}
