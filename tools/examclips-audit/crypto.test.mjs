import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtemp, readFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const pair = generateKeyPairSync('rsa', {modulusLength: 2048, publicKeyEncoding: {type:'spki',format:'pem'}, privateKeyEncoding: {type:'pkcs8',format:'pem'}});
const context = {purpose:'credentials',repository:'MakSoS1/analytics_test',branch:'qa/examclips-audit-2026-11-11',runId:'123456',runAttempt:'1',caseId:'en07'};
async function api() {
  const mod = await import('./crypto.mjs').catch(() => null);
  assert.ok(mod, 'Run-bound hybrid encryption must be implemented');
  return mod;
}

test('credential envelope round-trips a long payload without exposing its plaintext', async () => {
  const {seal,open} = await api();
  const value = {email:'audit-fixture@example.invalid',password:'test-only-value-'.repeat(100)};
  const envelope = seal(Buffer.from(JSON.stringify(value)),pair.publicKey,context);
  assert.equal(JSON.stringify(envelope).includes(value.email),false);
  assert.deepEqual(JSON.parse(open(envelope,pair.privateKey,context).toString()),value);
});

test('a credential envelope from another run, attempt or case is rejected', async () => {
  const {seal,open} = await api();
  const envelope = seal(Buffer.from('test-only'),pair.publicKey,context);
  assert.throws(()=>open(envelope,pair.privateKey,{...context,runId:'123457'}),/context/i);
  assert.throws(()=>open(envelope,pair.privateKey,{...context,runAttempt:'2'}),/context/i);
  assert.throws(()=>open(envelope,pair.privateKey,{...context,caseId:'ru01'}),/context/i);
});

test('ciphertext tampering is rejected by authenticated decryption', async () => {
  const {seal,open} = await api();
  const envelope = seal(Buffer.from('test-only'),pair.publicKey,context);
  const changed = structuredClone(envelope);
  const bytes = Buffer.from(changed.ciphertext,'base64'); bytes[0] ^= 1;
  changed.ciphertext = bytes.toString('base64');
  assert.throws(()=>open(changed,pair.privateKey,context));
});

test('streamed encrypted evidence restores exact ZIP bytes and removes failed plaintext', async () => {
  const {sealFile,openFile} = await api();
  const dir = await mkdtemp(join(tmpdir(),'examclips-crypto-test-'));
  try {
    const source=join(dir,'in.zip'),encrypted=join(dir,'out.enc'),restored=join(dir,'restored.zip');
    const bytes=Buffer.concat([Buffer.from('PK\x03\x04'),Buffer.alloc(250000,7)]);
    await writeFile(source,bytes);
    const metadata=await sealFile(source,encrypted,pair.publicKey,{...context,purpose:'evidence'});
    await assert.rejects(openFile(encrypted,restored,metadata,pair.privateKey,{...context,purpose:'evidence',caseId:'ru01'}),/context/i);
    await assert.rejects(readFile(restored),/ENOENT/);
    await openFile(encrypted,restored,metadata,pair.privateKey,{...context,purpose:'evidence'});
    assert.deepEqual(await readFile(restored),bytes);
    metadata.tag=Buffer.alloc(16).toString('base64');
    await assert.rejects(openFile(encrypted,restored,metadata,pair.privateKey,{...context,purpose:'evidence'}));
    await assert.rejects(readFile(restored),/ENOENT/);
  } finally { await rm(dir,{recursive:true,force:true}); }
});
