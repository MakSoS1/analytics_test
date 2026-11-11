import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const source = await readFile(join(here, 'client-bundle.js'), 'utf8');
const manifest = JSON.parse(
  await readFile(join(here, 'client-bundle.manifest.json'), 'utf8')
);
const bundleSha256 = createHash('sha256').update(source).digest('hex');
if (bundleSha256 !== manifest.bundleSha256) {
  throw new Error('CLIENT_BUNDLE_MANIFEST_MISMATCH');
}
const context = { setTimeout, clearTimeout };
const result = runInNewContext(
  source + '\n;({ selfTests: AuditCrypto.selfTests, versions: AuditCrypto.versions,' +
  ' globals: { crypto: typeof crypto, Buffer: typeof Buffer,' +
  ' TextEncoder: typeof TextEncoder, process: typeof process, require: typeof require } });',
  context,
  { timeout: 30000, displayErrors: true }
);
for (const value of Object.values(result.globals)) {
  if (value !== 'undefined') throw new Error('TEST_CONTEXT_HAS_NATIVE_CRYPTO_CAPABILITY');
}
for (const name of [
  'sha256Abc', 'rfc5869Case1', 'aes256GcmKnownVector',
  'alteredTagRejected', 'alteredAadRejected', 'rngForbidden'
]) {
  if (result.selfTests[name] !== true) throw new Error('CLIENT_SELF_TEST_INCOMPLETE');
}
if (result.selfTests.rngCallsDuringCryptoTests !== 0) {
  throw new Error('CLIENT_SELF_TEST_USED_RNG');
}
console.log(JSON.stringify({
  clientTests: 'passed',
  bundleSha256,
  ...result,
  scope: 'Public known-answer and failure tests in an isolated VM; no real keys or grants.'
}));
