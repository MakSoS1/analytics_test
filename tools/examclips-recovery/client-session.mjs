const REPOSITORY = 'MakSoS1/analytics_test';
const BRANCH = 'qa/examclips-audit-2026-11-11';
const PROTOCOL = 'examclips-review-session-v1';
const MAXINPUT = 2 * 1024 ** 2;
const MAXREPLY = 20 * 1024 ** 2;
const MAXRECORD = 8 * 1024 ** 2;
const MAXRECORDTOTAL = 12 * 1024 ** 2;
const PARTCHARS = 600000;
const usedMaterials = new WeakSet();

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function object(value, code = 'OBJECT_REQUIRED') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  return value;
}
function bytes(value, length) {
  if (!(value instanceof Uint8Array)) fail('UINT8ARRAY_REQUIRED');
  if (length !== undefined && value.length !== length) fail('INVALID_BYTE_LENGTH');
  return value;
}
function digest(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('INVALID_SHA256');
  return value;
}
function integer(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}
function exactKeys(value, expected, code) {
  object(value, code);
  const actual = Object.keys(value).sort();
  if (actual.join('\0') !== [...expected].sort().join('\0')) fail(code);
}
function canonical(value) {
  object(value);
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
  ));
}
function toBase64(value) {
  bytes(value);
  if (typeof value.toBase64 !== 'function') fail('BASE64_RUNTIME_UNAVAILABLE');
  return value.toBase64();
}
function fromBase64(value, maximum = MAXREPLY) {
  integer(maximum, 0, MAXREPLY, 'BASE64_SIZE_LIMIT');
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(maximum / 3) ||
      value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(value)) fail('INVALID_BASE64');
  const padding = value.indexOf('=');
  if (padding !== -1 && (padding < value.length - 2 ||
      !/^={1,2}$/.test(value.slice(padding)))) fail('INVALID_BASE64');
  if (typeof Uint8Array.fromBase64 !== 'function') fail('BASE64_RUNTIME_UNAVAILABLE');
  let result;
  try { result = Uint8Array.fromBase64(value, { lastChunkHandling: 'strict' }); }
  catch { fail('INVALID_BASE64'); }
  if (result.length > maximum || toBase64(result) !== value) fail('INVALID_BASE64');
  return result;
}
function utf8Text(C, value) {
  bytes(value);
  try { return C.forge.util.decodeUtf8(C.toBinary(value)); }
  catch { fail('INVALID_UTF8'); }
}
function hash(C, value) {
  return C.toHex(C.sha256(bytes(value)));
}
function identity(value) {
  object(value, 'INVALID_SESSION_IDENTITY');
  if (value.repository !== REPOSITORY || value.branch !== BRANCH ||
      !['root', 'ru', 'en'].includes(value.caseId)) fail('INVALID_SESSION_IDENTITY');
  for (const name of ['runId', 'runAttempt']) {
    if (typeof value[name] !== 'string' || !/^[1-9]\d{0,19}$/.test(value[name])) {
      fail('INVALID_SESSION_IDENTITY');
    }
  }
  return {
    repository: value.repository, branch: value.branch, runId: value.runId,
    runAttempt: value.runAttempt, caseId: value.caseId
  };
}
function contextFor(descriptor, purpose, extra = {}) {
  const core = { purpose, ...identity(descriptor) };
  if (purpose === 'review-reply') {
    exactKeys(extra, ['sequence', 'key'], 'INVALID_REPLY_CONTEXT');
    integer(extra.sequence, 0, 10000, 'INVALID_REPLY_CONTEXT');
    if (extra.key !== null && (typeof extra.key !== 'string' ||
        !/^(?:native-)?(?:rul|enl)\d{2}$/.test(extra.key))) fail('INVALID_REPLY_CONTEXT');
    return { ...core, sequence: extra.sequence, key: extra.key };
  }
  if (!['review-recovery-fixture', 'review-recovery-input', 'review-fixture-reply'].includes(purpose)) {
    fail('INVALID_SESSION_PURPOSE');
  }
  if (Object.keys(extra).length !== 0) fail('INVALID_REPLY_CONTEXT');
  return core;
}
function validContext(value) {
  object(value, 'INVALID_REPLY_CONTEXT');
  const isReply = value.purpose === 'review-reply';
  const expected = contextFor(value, value.purpose,
    isReply ? { sequence: value.sequence, key: value.key } : {});
  exactKeys(value, Object.keys(expected), 'INVALID_REPLY_CONTEXT');
  return value;
}
function verifyDescriptor(C, descriptor, expected = {}, now = Date.now()) {
  object(descriptor, 'INVALID_DESCRIPTOR');
  identity(descriptor);
  if (descriptor.version !== 1 || descriptor.purpose !== 'review-recovery-input' ||
      typeof descriptor.publicKey !== 'string' || descriptor.publicKey.length > 8192 ||
      !/^-----BEGIN PUBLIC KEY-----\r?\n[\s\S]+\r?\n-----END PUBLIC KEY-----\s*$/.test(descriptor.publicKey) ||
      typeof descriptor.sourceCommit !== 'string' || !/^[0-9a-f]{40}$/.test(descriptor.sourceCommit)) {
    fail('INVALID_DESCRIPTOR');
  }
  digest(descriptor.keySha256); digest(descriptor.bundleSha256);
  if (hash(C, C.utf8(descriptor.publicKey.trim())) !== descriptor.keySha256) {
    fail('DESCRIPTOR_KEY_HASH_MISMATCH');
  }
  const created = Date.parse(descriptor.createdAt), expires = Date.parse(descriptor.expiresAt);
  if (!Number.isFinite(now) || !Number.isFinite(created) || !Number.isFinite(expires) ||
      expires <= created || expires - created > 46 * 60000 || created > now + 120000) {
    fail('INVALID_DESCRIPTOR_TIME');
  }
  if (expires <= now) fail('DESCRIPTOR_EXPIRED');
  object(expected, 'INVALID_DESCRIPTOR_EXPECTATION');
  const permitted = ['repository', 'branch', 'runId', 'runAttempt', 'caseId',
    'keySha256', 'bundleSha256', 'sourceCommit'];
  for (const [key, value] of Object.entries(expected)) {
    if (!permitted.includes(key) || descriptor[key] !== value) fail('DESCRIPTOR_EXPECTATION_MISMATCH');
  }
  return descriptor;
}
function bindingFor(descriptor) {
  return canonical({
    protocol: PROTOCOL, ...identity(descriptor),
    keySha256: digest(descriptor.keySha256), bundleSha256: digest(descriptor.bundleSha256)
  });
}
function deriveMaterials(C, descriptor, entropy32) {
  verifyDescriptor(C, descriptor);
  bytes(entropy32, 32);
  const binding = bindingFor(descriptor);
  const salt = C.sha256(C.utf8(PROTOCOL + '|hkdf-salt|' + binding));
  const derive = (label, length) => C.hkdf(C.sha256, entropy32, salt,
    C.utf8(PROTOCOL + '|' + label + '|' + binding), length);
  return {
    binding,
    key: derive('envelope-aes256-key', 32),
    iv: derive('envelope-gcm-iv', 12),
    oaepSeed: derive('envelope-oaep-sha256-seed', 32),
    replyKey: derive('reply-aes256-key', 32)
  };
}
function sealInput(C, descriptor, purpose, payload, materials) {
  verifyDescriptor(C, descriptor);
  if (!['review-recovery-fixture', 'review-recovery-input'].includes(purpose)) {
    fail('INVALID_SESSION_PURPOSE');
  }
  object(materials, 'INVALID_MATERIALS');
  bytes(materials.key, 32); bytes(materials.iv, 12); bytes(materials.oaepSeed, 32);
  if (usedMaterials.has(materials)) fail('MATERIALS_ALREADY_SEALED');
  if (purpose === 'review-recovery-input') {
    bytes(materials.replyKey, 32);
    if (materials.binding !== bindingFor(descriptor)) fail('MATERIALS_CONTEXT_MISMATCH');
    if (!payload || payload.version !== 1 || payload.bundleSha256 !== descriptor.bundleSha256 ||
        payload.replyKey !== toBase64(materials.replyKey)) fail('INPUT_PAYLOAD_BINDING_MISMATCH');
  } else {
    const known = { fixture: 'examclips-review-bridge', bytes: [0, 1, 127, 128, 255], version: 1 };
    if (canonical(payload) !== canonical(known)) fail('PUBLIC_FIXTURE_PAYLOAD_MISMATCH');
  }
  const serialized = JSON.stringify(payload);
  if (typeof serialized !== 'string') fail('INVALID_INPUT_PAYLOAD');
  const plaintext = C.utf8(serialized);
  if (plaintext.length > MAXINPUT) fail('INPUT_SIZE_LIMIT');
  const context = contextFor(descriptor, purpose);
  const header = {
    version: 1, algorithm: 'AES-256-GCM+RSA-OAEP-SHA256',
    keySha256: descriptor.keySha256, context
  };
  usedMaterials.add(materials);
  const encrypted = C.aesGcmEncrypt(materials.key, materials.iv, plaintext, C.utf8(canonical(header)));
  const wrapped = C.wrapKeyOaep(descriptor.publicKey, materials.key,
    materials.oaepSeed, new Uint8Array(0));
  return {
    ...header, wrappedKey: toBase64(wrapped), iv: toBase64(materials.iv),
    tag: toBase64(encrypted.tag), ciphertext: toBase64(encrypted.ciphertext)
  };
}
function publicFixture(C, descriptor) {
  const payload = { fixture: 'examclips-review-bridge', bytes: [0, 1, 127, 128, 255], version: 1 };
  const materials = {
    key: new Uint8Array(32).fill(0x24), iv: new Uint8Array(12).fill(0x17),
    oaepSeed: new Uint8Array(32).fill(0x42)
  };
  return {
    envelope: sealInput(C, descriptor, 'review-recovery-fixture', payload, materials),
    replyKeyBase64: toBase64(new Uint8Array(32).fill(0x13)),
    expectedReplyContext: contextFor(descriptor, 'review-fixture-reply')
  };
}
function replyMetadata(envelope, expectedContext, allowParts) {
  object(envelope, 'INVALID_REPLY_ENVELOPE');
  if (envelope.version !== 1 || envelope.algorithm !== 'AES-256-GCM') {
    fail('INVALID_REPLY_ALGORITHM');
  }
  validContext(expectedContext); validContext(envelope.context);
  if (!['review-reply', 'review-fixture-reply'].includes(expectedContext.purpose)) {
    fail('INVALID_REPLY_CONTEXT');
  }
  if (canonical(envelope.context) !== canonical(expectedContext)) fail('REPLY_CONTEXT_MISMATCH');
  integer(envelope.plaintextBytes, 2, MAXREPLY, 'REPLY_SIZE_LIMIT');
  digest(envelope.sha256);
  const hasCiphertext = Object.hasOwn(envelope, 'ciphertext');
  const hasParts = Object.hasOwn(envelope, 'ciphertextParts');
  if (hasCiphertext === hasParts || (hasParts && !allowParts)) fail('INVALID_REPLY_TRANSPORT');
  const transport = hasParts ? 'ciphertextParts' : 'ciphertext';
  exactKeys(envelope, ['version', 'algorithm', 'context', 'plaintextBytes',
    'sha256', 'iv', 'tag', transport], 'INVALID_REPLY_FIELDS');
  if (fromBase64(envelope.iv, 12).length !== 12 ||
      fromBase64(envelope.tag, 16).length !== 16) fail('INVALID_REPLY_LENGTH');
  return {
    version: envelope.version, algorithm: envelope.algorithm,
    context: envelope.context, plaintextBytes: envelope.plaintextBytes, sha256: envelope.sha256
  };
}
function assembleReply(C, envelope, fetchedParts = [], expectedContext) {
  replyMetadata(envelope, expectedContext, true);
  if (!Array.isArray(fetchedParts)) fail('CIPHERTEXT_PART_COUNT');
  const characters = 4 * Math.ceil(envelope.plaintextBytes / 3);
  if (Object.hasOwn(envelope, 'ciphertext')) {
    if (fetchedParts.length !== 0 || typeof envelope.ciphertext !== 'string' ||
        envelope.ciphertext.length !== characters) fail('CIPHERTEXT_LENGTH_MISMATCH');
    fromBase64(envelope.ciphertext, MAXREPLY);
    return envelope;
  }
  if (envelope.context.purpose !== 'review-reply' || characters <= PARTCHARS ||
      !Array.isArray(envelope.ciphertextParts)) fail('INVALID_CIPHERTEXT_PARTS');
  const count = Math.ceil(characters / PARTCHARS);
  if (count > 48 || envelope.ciphertextParts.length !== count || fetchedParts.length !== count) {
    fail('CIPHERTEXT_PART_COUNT');
  }
  const prefix = '.audit-recovery/' + envelope.context.runId + '/' +
    envelope.context.runAttempt + '/' + envelope.context.caseId + '/responses/' +
    String(envelope.context.sequence).padStart(5, '0');
  const received = new Map();
  for (const fetched of fetchedParts) {
    exactKeys(fetched, ['path', 'content'], 'INVALID_CIPHERTEXT_PART_RECORD');
    if (typeof fetched.path !== 'string' || received.has(fetched.path) ||
        typeof fetched.content !== 'string' || fetched.content.length > PARTCHARS + 100) {
      fail('INVALID_CIPHERTEXT_PART_RECORD');
    }
    received.set(fetched.path, fetched.content);
  }
  const fragments = [];
  for (let i = 0; i < count; i++) {
    const entry = envelope.ciphertextParts[i], index = i + 1;
    exactKeys(entry, ['path', 'index', 'characters', 'sha256'], 'INVALID_CIPHERTEXT_PART_METADATA');
    const expectedPath = prefix + '-p' + String(index).padStart(4, '0') + '.json';
    if (entry.path !== expectedPath || entry.index !== index) fail('CIPHERTEXT_PART_PATH');
    const expectedChars = Math.min(PARTCHARS, characters - i * PARTCHARS);
    if (entry.characters !== expectedChars) fail('CIPHERTEXT_PART_LENGTH');
    digest(entry.sha256);
    if (!received.has(entry.path)) fail('CIPHERTEXT_PART_PATH');
    let piece;
    try { piece = JSON.parse(received.get(entry.path)); }
    catch { fail('INVALID_CIPHERTEXT_PART_JSON'); }
    exactKeys(piece, ['index', 'ciphertext'], 'INVALID_CIPHERTEXT_PART_FIELDS');
    if (piece.index !== index || typeof piece.ciphertext !== 'string' ||
        piece.ciphertext.length !== expectedChars) fail('CIPHERTEXT_PART_LENGTH');
    fromBase64(piece.ciphertext, Math.ceil(PARTCHARS * 3 / 4));
    if (hash(C, C.utf8(piece.ciphertext)) !== entry.sha256) fail('CIPHERTEXT_PART_HASH_MISMATCH');
    fragments.push(piece.ciphertext);
  }
  const ciphertext = fragments.join('');
  if (ciphertext.length !== characters) fail('CIPHERTEXT_LENGTH_MISMATCH');
  const { ciphertextParts, ...rest } = envelope;
  return { ...rest, ciphertext };
}
function safePath(value) {
  if (typeof value !== 'string' || !value || value.length > 500 ||
      value.startsWith('/') || /[\\\x00-\x1f\x7f]/.test(value) ||
      value.split('/').some(x => !x || x === '.' || x === '..')) fail('INVALID_RECORD_PATH');
  return value;
}
function verifyRecord(C, record) {
  object(record, 'INVALID_FILE_RECORD');
  exactKeys(record, ['path', 'bytes', 'sha256', 'mime', 'base64'], 'INVALID_FILE_RECORD');
  safePath(record.path);
  integer(record.bytes, 0, MAXRECORD, 'RECORD_SIZE_LIMIT');
  digest(record.sha256);
  if (!['image/png', 'image/jpeg', 'application/octet-stream'].includes(record.mime)) {
    fail('INVALID_RECORD_MIME');
  }
  const decoded = fromBase64(record.base64, MAXRECORD);
  if (decoded.length !== record.bytes) fail('RECORD_LENGTH_MISMATCH');
  if (hash(C, decoded) !== record.sha256) fail('RECORD_HASH_MISMATCH');
  return decoded;
}
function verifyFileRecords(C, records) {
  if (!Array.isArray(records) || records.length > 12) fail('INVALID_FILE_RECORDS');
  let total = 0;
  const paths = new Set();
  for (const record of records) {
    object(record, 'INVALID_FILE_RECORD');
    integer(record.bytes, 0, MAXRECORD, 'RECORD_SIZE_LIMIT');
    total += record.bytes;
    if (total > MAXRECORDTOTAL) fail('RECORD_TOTAL_SIZE_LIMIT');
    if (paths.has(record.path)) fail('DUPLICATE_RECORD_PATH');
    paths.add(record.path);
    verifyRecord(C, record);
  }
  return records;
}
function verifiedText(C, record) {
  const decoded = verifyRecord(C, record);
  if (record.mime !== 'application/octet-stream') fail('TEXT_RECORD_REQUIRED');
  return utf8Text(C, decoded);
}
function imageDataUrl(C, record) {
  const decoded = verifyRecord(C, record);
  const png = record.mime === 'image/png' && decoded.length >= 8 &&
    [137, 80, 78, 71, 13, 10, 26, 10].every((value, i) => decoded[i] === value);
  const jpeg = record.mime === 'image/jpeg' && decoded.length >= 4 &&
    decoded[0] === 255 && decoded[1] === 216 && decoded[2] === 255 &&
    decoded[decoded.length - 2] === 255 && decoded[decoded.length - 1] === 217;
  if (!png && !jpeg) fail('IMAGE_SIGNATURE_MISMATCH');
  return 'data:' + record.mime + ';base64,' + toBase64(decoded);
}
function decryptReply(C, envelope, replyKey, expectedContext) {
  bytes(replyKey, 32);
  const metadata = replyMetadata(envelope, expectedContext, false);
  const ciphertext = fromBase64(envelope.ciphertext, MAXREPLY);
  if (ciphertext.length !== envelope.plaintextBytes) fail('CIPHERTEXT_LENGTH_MISMATCH');
  const plaintext = C.aesGcmDecrypt(replyKey, fromBase64(envelope.iv, 12),
    ciphertext, C.utf8(canonical(metadata)), fromBase64(envelope.tag, 16));
  if (plaintext.length !== envelope.plaintextBytes) fail('REPLY_PLAINTEXT_LENGTH_MISMATCH');
  if (hash(C, plaintext) !== envelope.sha256) fail('REPLY_PLAINTEXT_HASH_MISMATCH');
  const text = utf8Text(C, plaintext);
  let value;
  try { value = JSON.parse(text); }
  catch { fail('INVALID_REPLY_JSON'); }
  object(value, 'INVALID_REPLY_VALUE');
  if (envelope.context.purpose === 'review-reply' &&
      (value.key ?? null) !== envelope.context.key) fail('REPLY_VALUE_KEY_MISMATCH');
  if (Object.hasOwn(value, 'files')) verifyFileRecords(C, value.files);
  return value;
}
function sasGrant(transfer, expectedId, now) {
  object(transfer, 'INVALID_LIBRARY_TRANSFER');
  if (typeof expectedId !== 'string' || !/^libfile[_-][A-Za-z0-9_-]{3,120}$/.test(expectedId) ||
      transfer.library_file_id !== expectedId || transfer.workspace_path ||
      typeof transfer.download_url !== 'string' || transfer.download_url.length > 16384) {
    fail('INVALID_LIBRARY_TRANSFER');
  }
  for (const [name, value] of Object.entries(transfer)) {
    if (/headers$/i.test(name) && value !== null && value !== undefined &&
        (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 0)) {
      fail('SAS_HEADERS_NOT_SUPPORTED');
    }
  }
  const match = transfer.download_url.match(
    /^https:\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.blob\.core\.windows\.net)|(?:sdmntpr[a-z0-9-]+\.oaiusercontent\.com))(\/[^?#\s\\]+)\?([^#\s]+)$/
  );
  if (!match) fail('SAS_AZURE_HTTPS_REQUIRED');
  let path;
  try { path = decodeURIComponent(match[2]); }
  catch { fail('INVALID_SAS_PATH'); }
  if (/[\\\x00-\x1f\x7f]/.test(path) || path.split('/').slice(1).length < 2 ||
      path.split('/').slice(1).some(x => !x || x === '.' || x === '..')) fail('INVALID_SAS_PATH');
  const query = Object.create(null);
  for (const field of match[3].split('&')) {
    const at = field.indexOf('=');
    if (at < 1) fail('INVALID_SAS_QUERY');
    let name, value;
    try {
      name = decodeURIComponent(field.slice(0, at).replace(/\+/g, ' '));
      value = decodeURIComponent(field.slice(at + 1).replace(/\+/g, ' '));
    } catch { fail('INVALID_SAS_QUERY'); }
    if (Object.hasOwn(query, name)) fail('SAS_DUPLICATE_QUERY_FIELD');
    query[name] = value;
  }
  if (query.sr !== 'b' || query.sp !== 'r' || (query.spr !== undefined && query.spr !== 'https') ||
      query.ss !== undefined || query.srt !== undefined) fail('SAS_READ_BLOB_REQUIRED');
  for (const field of ['skoid', 'sktid', 'skt', 'ske', 'sks', 'skv', 'sv', 'se', 'sig']) {
    if (typeof query[field] !== 'string' || !query[field]) fail('SAS_USER_DELEGATION_REQUIRED');
  }
  if (query.sks !== 'b') fail('SAS_USER_DELEGATION_REQUIRED');
  const expires = Date.parse(query.se), keyStart = Date.parse(query.skt), keyEnd = Date.parse(query.ske);
  if (!Number.isFinite(now) || !Number.isFinite(expires) || !Number.isFinite(keyStart) ||
      !Number.isFinite(keyEnd) || keyStart > now + 300000 || keyEnd < expires) fail('INVALID_SAS_TIME');
  if (expires <= now + 30000) fail('SAS_EXPIRED_OR_EXPIRING');
  const signature = fromBase64(query.sig, 32);
  if (signature.length !== 32) fail('SAS_SIGNATURE_LENGTH');
  return { signature, resource: match[1] + path, expiresAt: new Date(expires).toISOString() };
}
function parseGrants(transferA, transferB, expectedA, expectedB, now = Date.now()) {
  if (typeof expectedA !== 'string' || typeof expectedB !== 'string' || expectedA === expectedB) {
    fail('LIBRARY_IDS_NOT_DISTINCT');
  }
  const a = sasGrant(transferA, expectedA, now), b = sasGrant(transferB, expectedB, now);
  if (a.resource === b.resource) fail('SAS_RESOURCES_NOT_DISTINCT');
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= a.signature[i] ^ b.signature[i];
  if (difference === 0) fail('SAS_SIGNATURES_NOT_DISTINCT');
  a.signature.fill(0);
  return {
    transfer: transferA, entropy32: b.signature,
    expiresAtA: a.expiresAt, expiresAtB: b.expiresAt
  };
}

export {
  canonical, toBase64, fromBase64, utf8Text, contextFor, verifyDescriptor,
  deriveMaterials, sealInput, publicFixture, assembleReply, decryptReply,
  verifyRecord, verifyFileRecords, verifiedText, imageDataUrl, parseGrants
};
