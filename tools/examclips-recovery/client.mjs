import forge from 'node-forge';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const versions = Object.freeze({
  forge: '1.4.3',
  nobleHashes: '2.4.0',
  esbuild: '0.28.2'
});
let forbiddenRngCalls = 0;
function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function forbiddenRng() {
  forbiddenRngCalls++;
  fail('RNG_FORBIDDEN');
}
function lock(object, name, value) {
  const current = Object.getOwnPropertyDescriptor(object, name);
  if (current && current.configurable === false) {
    if (current.value !== value) fail('RNG_GUARD_NOT_INSTALLABLE');
    return;
  }
  Object.defineProperty(object, name, {
    value, writable: false, configurable: false, enumerable: false
  });
}
function disableRng() {
  forge.options.usePureJavaScript = true;
  lock(Math, 'random', forbiddenRng);
  for (const name of [
    'getBytes', 'getBytesSync', 'generate', 'generateSync',
    'seedFile', 'seedFileSync', 'createInstance'
  ]) lock(forge.random, name, forbiddenRng);
  lock(forge.prng, 'create', forbiddenRng);
  lock(forge, 'random', forge.random);
}
disableRng();

function bytes(value, length) {
  if (!(value instanceof Uint8Array)) fail('UINT8ARRAY_REQUIRED');
  if (length !== undefined && value.length !== length) fail('INVALID_BYTE_LENGTH');
  return value;
}
function fromHex(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(value)) {
    fail('INVALID_HEX');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function toHex(value) {
  bytes(value);
  let out = '';
  for (const octet of value) out += octet.toString(16).padStart(2, '0');
  return out;
}
function toBinary(value) {
  bytes(value);
  let out = '';
  for (const octet of value) out += String.fromCharCode(octet);
  return out;
}
function fromBinary(value) {
  if (typeof value !== 'string') fail('BINARY_STRING_REQUIRED');
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const octet = value.charCodeAt(i);
    if (octet > 255) fail('NON_BYTE_CHARACTER');
    out[i] = octet;
  }
  return out;
}
function utf8(value) {
  if (typeof value !== 'string') fail('STRING_REQUIRED');
  return fromBinary(forge.util.encodeUtf8(value));
}
function aesGcmEncrypt(key, iv, plaintext, aad) {
  bytes(key, 32); bytes(iv, 12); bytes(plaintext); bytes(aad);
  const cipher = forge.cipher.createCipher('AES-GCM', toBinary(key));
  cipher.start({ iv: toBinary(iv), additionalData: toBinary(aad), tagLength: 128 });
  cipher.update(forge.util.createBuffer(toBinary(plaintext)));
  if (cipher.finish() !== true) fail('AES_GCM_ENCRYPT_FAILED');
  const tag = fromBinary(cipher.mode.tag.getBytes());
  bytes(tag, 16);
  return { ciphertext: fromBinary(cipher.output.getBytes()), tag };
}
function aesGcmDecrypt(key, iv, ciphertext, aad, tag) {
  bytes(key, 32); bytes(iv, 12); bytes(ciphertext); bytes(aad); bytes(tag, 16);
  const decipher = forge.cipher.createDecipher('AES-GCM', toBinary(key));
  decipher.start({
    iv: toBinary(iv), additionalData: toBinary(aad),
    tag: toBinary(tag), tagLength: 128
  });
  decipher.update(forge.util.createBuffer(toBinary(ciphertext)));
  if (decipher.finish() !== true) {
    decipher.output.clear();
    fail('AES_GCM_AUTHENTICATION_FAILED');
  }
  return fromBinary(decipher.output.getBytes());
}
function wrapKeyOaep(publicKeyPem, key, seed, label) {
  if (typeof publicKeyPem !== 'string') fail('PUBLIC_PEM_REQUIRED');
  bytes(key, 32); bytes(seed, 32); bytes(label);
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  if (publicKey.n.bitLength() !== 4096 || publicKey.e.toString(10) !== '65537') {
    fail('EXPECTED_RSA4096_E65537');
  }
  const result = fromBinary(publicKey.encrypt(toBinary(key), 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha256.create() },
    seed: toBinary(seed),
    label: toBinary(label)
  }));
  bytes(result, 512);
  return result;
}
function expectEqual(actual, expected, label) {
  if (actual !== expected) fail('SELF_TEST_FAILED_' + label);
}
function expectError(operation, code) {
  try { operation(); }
  catch (error) {
    if (error && error.code === code) return;
    throw error;
  }
  fail('SELF_TEST_EXPECTED_' + code);
}
function runSelfTests() {
  const before = forbiddenRngCalls;
  const abc = new Uint8Array([97, 98, 99]);
  expectEqual(toHex(sha256(abc)),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'SHA256_ABC');
  const okm = hkdf(sha256, fromHex('0b'.repeat(22)),
    fromHex('000102030405060708090a0b0c'),
    fromHex('f0f1f2f3f4f5f6f7f8f9'), 42);
  expectEqual(toHex(okm),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    'RFC5869_CASE1');
  const key = new Uint8Array(32);
  const iv = new Uint8Array(12);
  const plaintext = new Uint8Array(16);
  const aad = new Uint8Array(0);
  const encrypted = aesGcmEncrypt(key, iv, plaintext, aad);
  expectEqual(toHex(encrypted.ciphertext),
    'cea7403d4d606b6e074ec5d3baf39d18', 'AES256_GCM_CIPHERTEXT');
  expectEqual(toHex(encrypted.tag),
    'd0d1c8a799996bf0265b98b5d48ab919', 'AES256_GCM_TAG');
  expectEqual(toHex(aesGcmDecrypt(key, iv, encrypted.ciphertext, aad, encrypted.tag)),
    '00000000000000000000000000000000', 'AES256_GCM_DECRYPT');
  const badTag = encrypted.tag.slice();
  badTag[0] ^= 1;
  expectError(() => aesGcmDecrypt(key, iv, encrypted.ciphertext, aad, badTag),
    'AES_GCM_AUTHENTICATION_FAILED');
  expectError(() => aesGcmDecrypt(key, iv, encrypted.ciphertext, new Uint8Array([1]), encrypted.tag),
    'AES_GCM_AUTHENTICATION_FAILED');
  expectEqual(forbiddenRngCalls, before, 'NO_RNG_DURING_CRYPTO');
  expectError(() => forge.random.getBytesSync(1), 'RNG_FORBIDDEN');
  expectError(() => forge.random.getBytes(1), 'RNG_FORBIDDEN');
  expectError(() => Math.random(), 'RNG_FORBIDDEN');
  return Object.freeze({
    sha256Abc: true, rfc5869Case1: true, aes256GcmKnownVector: true,
    alteredTagRejected: true, alteredAadRejected: true,
    rngForbidden: true, rngCallsDuringCryptoTests: 0
  });
}
const selfTests = runSelfTests();

export {
  forge, hkdf, sha256, versions, selfTests, runSelfTests, disableRng,
  fromHex, toHex, toBinary, fromBinary, utf8,
  aesGcmEncrypt, aesGcmDecrypt, wrapKeyOaep
};
