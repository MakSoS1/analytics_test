import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext, runInContext, createContext } from 'node:vm';
import { generateKeyPairSync, createHash, createCipheriv, hkdfSync } from 'node:crypto';
import { open } from '../examclips-audit/crypto.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const bundle = await readFile(join(here, 'client-bundle.js'), 'utf8');
const source = await readFile(join(here, 'client-session.mjs'), 'utf8');
const exportBlock = source.match(/\nexport \{([\s\S]+?)\};?\s*$/);
assert.ok(exportBlock, 'utility exposes a single explicit export block');
const names = exportBlock[1].split(',').map(x => x.trim()).filter(Boolean);
assert.ok(names.every(x => /^[A-Za-z][A-Za-z0-9]*$/.test(x)));
const sandbox = createContext({ setTimeout, clearTimeout });
runInContext(bundle + '\n' + source.slice(0, exportBlock.index) +
  '\n;globalThis.S = {' + names.join(',') + '};', sandbox, { timeout: 30000 });
const evaluate = code => runInContext(code, sandbox, { timeout: 30000 });
const put = (name, value) => evaluate('globalThis.' + name + ' = JSON.parse(' +
  JSON.stringify(JSON.stringify(value)) + ');');
const result = code => JSON.parse(evaluate('JSON.stringify(' + code + ')'));
const sha = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(Object.fromEntries(
  Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));
const expectCode = (code, expected) => {
  const actual = evaluate('(() => { try { ' + code +
    '; return null; } catch (e) { return e.code || e.message; } })()');
  assert.equal(actual, expected);
};
const now = Date.now();
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 4096, publicExponent: 65537,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const descriptor = {
  version: 1, repository: 'MakSoS1/analytics_test',
  branch: 'qa/examclips-audit-2026-11-11', runId: '1234567',
  runAttempt: '1', caseId: 'en', purpose: 'review-recovery-input',
  sourceCommit: 'a'.repeat(40), createdAt: new Date(now).toISOString(),
  expiresAt: new Date(now + 45 * 60000).toISOString(), publicKey,
  keySha256: sha(publicKey.trim()), bundleSha256: sha(bundle),
  fixture: { fixture: 'examclips-review-bridge', bytes: [0, 1, 127, 128, 255], version: 1 }
};
put('desc', descriptor);
const inputContext = {
  purpose: 'review-recovery-input', repository: descriptor.repository,
  branch: descriptor.branch, runId: descriptor.runId,
  runAttempt: descriptor.runAttempt, caseId: descriptor.caseId
};
const fixture = result('S.publicFixture(AuditCrypto, desc)');
assert.deepEqual(JSON.parse(open(fixture.envelope, privateKey,
  { ...inputContext, purpose: 'review-recovery-fixture' }).toString('utf8')), descriptor.fixture);
assert.equal(fixture.replyKeyBase64, Buffer.alloc(32, 0x13).toString('base64'));
evaluate('globalThis.materials = S.deriveMaterials(AuditCrypto, desc, new Uint8Array(32).fill(0x6a));');
const derived = result('Object.fromEntries(["key","iv","oaepSeed","replyKey"].map(k => [k,S.toBase64(materials[k])]))');
const binding = canonical({
  protocol: 'examclips-review-session-v1', repository: descriptor.repository,
  branch: descriptor.branch, runId: descriptor.runId, runAttempt: descriptor.runAttempt,
  caseId: descriptor.caseId, keySha256: descriptor.keySha256, bundleSha256: descriptor.bundleSha256
});
const salt = createHash('sha256').update('examclips-review-session-v1|hkdf-salt|' + binding).digest();
for (const [name, label, length] of [
  ['key', 'envelope-aes256-key', 32], ['iv', 'envelope-gcm-iv', 12],
  ['oaepSeed', 'envelope-oaep-sha256-seed', 32], ['replyKey', 'reply-aes256-key', 32]
]) {
  const expected = Buffer.from(hkdfSync('sha256', Buffer.alloc(32, 0x6a), salt,
    Buffer.from('examclips-review-session-v1|' + label + '|' + binding), length));
  assert.equal(derived[name], expected.toString('base64'));
}
evaluate('globalThis.inputPayload = {version:1,bundleSha256:desc.bundleSha256,replyKey:S.toBase64(materials.replyKey),fixtureOnly:true};');
const sealed = result('S.sealInput(AuditCrypto, desc, "review-recovery-input", inputPayload, materials)');
assert.equal(JSON.parse(open(sealed, privateKey, inputContext).toString('utf8')).fixtureOnly, true);
expectCode('S.sealInput(AuditCrypto, desc, "review-recovery-input", inputPayload, materials)', 'MATERIALS_ALREADY_SEALED');
evaluate('globalThis.changed = {...desc, caseId:"ru"};');
assert.notEqual(result('S.toBase64(S.deriveMaterials(AuditCrypto, changed, new Uint8Array(32).fill(0x6a)).key)'), derived.key);
put('expired', { ...descriptor, createdAt: new Date(now - 50 * 60000).toISOString(), expiresAt: new Date(now - 5 * 60000).toISOString() });
expectCode('S.verifyDescriptor(AuditCrypto, expired)', 'DESCRIPTOR_EXPIRED');
put('badFingerprint', { ...descriptor, keySha256: '0'.repeat(64) });
expectCode('S.verifyDescriptor(AuditCrypto, badFingerprint)', 'DESCRIPTOR_KEY_HASH_MISMATCH');

const replyKey = Buffer.alloc(32, 0x13);
const replyContext = { purpose: 'review-reply', ...Object.fromEntries(
  Object.entries(inputContext).filter(([key]) => key !== 'purpose')), sequence: 1, key: 'enl02' };
function nodeReply(value, context = replyContext, extra = {}, raw = null) {
  const bytes = raw ?? Buffer.from(JSON.stringify(value));
  const metadata = { version: 1, algorithm: 'AES-256-GCM', context,
    plaintextBytes: bytes.length, sha256: sha(bytes), ...extra };
  const iv = Buffer.alloc(12, 0x55), cipher = createCipheriv('aes-256-gcm', replyKey, iv);
  cipher.setAAD(Buffer.from(canonical(metadata)));
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return { ...metadata, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64') };
}
evaluate('globalThis.replyKey = new Uint8Array(32).fill(0x13);');
put('expectedContext', replyContext);
const textBytes = Buffer.from('Пример: α + β = 2.\n');
const record = { path: 'enl02/reference.txt', bytes: textBytes.length, sha256: sha(textBytes),
  mime: 'application/octet-stream', base64: textBytes.toString('base64') };
const value = { status: 'ready', key: 'enl02', files: [record] };
put('reply', nodeReply(value));
assert.deepEqual(result('S.decryptReply(AuditCrypto, reply, replyKey, expectedContext)'), value);
put('record', record);
assert.equal(evaluate('S.verifiedText(AuditCrypto, record)'), textBytes.toString('utf8'));
const reordered = { key: 'enl02', sequence: 1, caseId: 'en', runAttempt: '1',
  runId: descriptor.runId, branch: descriptor.branch,
  repository: descriptor.repository, purpose: 'review-reply' };
put('replyReordered', nodeReply(value, reordered));
assert.equal(result('S.decryptReply(AuditCrypto, replyReordered, replyKey, expectedContext)').status, 'ready');
put('wrongContext', { ...replyContext, caseId: 'ru' });
expectCode('S.decryptReply(AuditCrypto, reply, replyKey, wrongContext)', 'REPLY_CONTEXT_MISMATCH');
put('badTag', { ...nodeReply(value), tag: Buffer.alloc(16).toString('base64') });
expectCode('S.decryptReply(AuditCrypto, badTag, replyKey, expectedContext)', 'AES_GCM_AUTHENTICATION_FAILED');
put('badHash', nodeReply(value, replyContext, { sha256: '0'.repeat(64) }));
expectCode('S.decryptReply(AuditCrypto, badHash, replyKey, expectedContext)', 'REPLY_PLAINTEXT_HASH_MISMATCH');
put('badSize', { ...nodeReply(value), plaintextBytes: 21 * 1024 ** 2 });
expectCode('S.decryptReply(AuditCrypto, badSize, replyKey, expectedContext)', 'REPLY_SIZE_LIMIT');
put('badRecord', { ...record, sha256: '0'.repeat(64) });
put('badRecordReply', nodeReply({ status: 'ready', key: 'enl02', files: [{ ...record, sha256: '0'.repeat(64) }] }));
expectCode('S.decryptReply(AuditCrypto, badRecordReply, replyKey, expectedContext)', 'RECORD_HASH_MISMATCH');
expectCode('S.verifiedText(AuditCrypto, badRecord)', 'RECORD_HASH_MISMATCH');
put('badUtf8Reply', nodeReply(null, replyContext, {}, Buffer.from([0xc0, 0xaf])));
expectCode('S.decryptReply(AuditCrypto, badUtf8Reply, replyKey, expectedContext)', 'INVALID_UTF8');
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a3foAAAAASUVORK5CYII=', 'base64');
put('pngRecord', { path: 'enl02/frame.png', bytes: png.length, sha256: sha(png),
  mime: 'image/png', base64: png.toString('base64') });
assert.equal(evaluate('S.imageDataUrl(AuditCrypto, pngRecord)'), 'data:image/png;base64,' + png.toString('base64'));
put('wrongImage', { ...record, mime: 'image/png' });
expectCode('S.imageDataUrl(AuditCrypto, wrongImage)', 'IMAGE_SIGNATURE_MISMATCH');

const large = nodeReply({ status: 'ready', key: 'enl02', text: 'x'.repeat(500000) });
const parts = [];
const manifest = { ...large, ciphertextParts: [] };
for (let start = 0, index = 1; start < large.ciphertext.length; start += 600000, index++) {
  const ciphertext = large.ciphertext.slice(start, start + 600000);
  const path = '.audit-recovery/1234567/1/en/responses/00001-p' + String(index).padStart(4, '0') + '.json';
  manifest.ciphertextParts.push({ path, index, characters: ciphertext.length, sha256: sha(ciphertext) });
  parts.push({ path, content: JSON.stringify({ index, ciphertext }) });
}
delete manifest.ciphertext;
put('manifest', manifest); put('parts', parts);
assert.equal(result('S.decryptReply(AuditCrypto, S.assembleReply(AuditCrypto, manifest, parts, expectedContext), replyKey, expectedContext)').text.length, 500000);
put('missingParts', parts.slice(0, 1));
expectCode('S.assembleReply(AuditCrypto, manifest, missingParts, expectedContext)', 'CIPHERTEXT_PART_COUNT');
put('corruptParts', parts.map((part, i) => i ? part : { ...part, content: part.content.replace(/"ciphertext":"./, '"ciphertext":"!') }));
expectCode('S.assembleReply(AuditCrypto, manifest, corruptParts, expectedContext)', 'INVALID_BASE64');
put('escapedManifest', { ...manifest, ciphertextParts: manifest.ciphertextParts.map((part, i) =>
  i ? part : { ...part, path: '.audit-recovery/1234567/1/ru/responses/00001-p0001.json' }) });
expectCode('S.assembleReply(AuditCrypto, escapedManifest, parts, expectedContext)', 'CIPHERTEXT_PART_PATH');
expectCode('S.fromBase64("Zh==")', 'INVALID_BASE64');
expectCode('S.fromBase64("Zg==\\n")', 'INVALID_BASE64');

function grant(id, octet, blob) {
  const start = new Date(now - 60000).toISOString();
  const expiry = new Date(now + 30 * 60000).toISOString();
  const query = new URLSearchParams({
    sr: 'b', sp: 'r', sv: '2025-05-05', spr: 'https',
    skoid: '11111111-1111-1111-1111-111111111111',
    sktid: '22222222-2222-2222-2222-222222222222',
    skt: start, ske: expiry, sks: 'b', skv: '2025-05-05', se: expiry,
    sig: Buffer.alloc(32, octet).toString('base64')
  });
  return { library_file_id: id, download_url: 'https://fixture.blob.core.windows.net/private/' + blob + '?' + query, headers: {} };
}
put('grantA', grant('libfile_fixture_key', 1, 'key'));
put('grantB', grant('libfile_fixture_entropy', 2, 'report'));
assert.equal(evaluate('S.parseGrants(grantA,grantB,"libfile_fixture_key","libfile_fixture_entropy").entropy32[0]'), 2);
put('sameSigB', grant('libfile_fixture_entropy', 1, 'report'));
expectCode('S.parseGrants(grantA,sameSigB,"libfile_fixture_key","libfile_fixture_entropy")', 'SAS_SIGNATURES_NOT_DISTINCT');
put('sameIdB', grant('libfile_fixture_key', 2, 'report'));
expectCode('S.parseGrants(grantA,sameIdB,"libfile_fixture_key","libfile_fixture_key")', 'LIBRARY_IDS_NOT_DISTINCT');
const hostile = grant('libfile_fixture_entropy', 2, 'report');
put('wrongHost', { ...hostile, download_url: hostile.download_url.replace('fixture.blob.core.windows.net', 'fixture.blob.core.windows.net.evil.test') });
expectCode('S.parseGrants(grantA,wrongHost,"libfile_fixture_key","libfile_fixture_entropy")', 'SAS_AZURE_HTTPS_REQUIRED');
put('writeGrant', { ...hostile, download_url: hostile.download_url.replace('sp=r&', 'sp=rw&') });
expectCode('S.parseGrants(grantA,writeGrant,"libfile_fixture_key","libfile_fixture_entropy")', 'SAS_READ_BLOB_REQUIRED');
put('headerGrant', { ...hostile, headers: { Authorization: 'fixture' } });
expectCode('S.parseGrants(grantA,headerGrant,"libfile_fixture_key","libfile_fixture_entropy")', 'SAS_HEADERS_NOT_SUPPORTED');
put('repeatedSig', { ...hostile, download_url: hostile.download_url + '&sig=x' });
expectCode('S.parseGrants(grantA,repeatedSig,"libfile_fixture_key","libfile_fixture_entropy")', 'SAS_DUPLICATE_QUERY_FIELD');
const absentGlobals = result('Object.fromEntries(["crypto","Buffer","TextEncoder","URL","process","require"].map(k => [k,typeof globalThis[k]]))');
for (const value of Object.values(absentGlobals)) assert.equal(value, 'undefined');
console.log(JSON.stringify({
  sessionTests: 'passed', sourceSha256: sha(source), bundleSha256: sha(bundle),
  checks: ['Node RSA-OAEP and AES-GCM interoperability', 'Node HKDF agreement and lane separation',
    'descriptor expiry and fingerprint', 'strict context and authenticated reply size/hash',
    'unchanged nested context AAD', 'file hash before text/image', 'strict UTF8',
    'bounded chunk assembly and corruption/path rejection', 'private grant fail-closed guards'],
  scope: 'Public generated fixture keypair and synthetic grants only; no recovery key or real grants.'
}));
