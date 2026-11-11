# Public browser crypto client for ExamClips recovery

These files build the public client used by the isolated recovery controller.
They contain no recovery keys, materialization grants, credentials or private
review assets. The controller/workflow is maintained separately.

## Pinned dependencies

| Package | Version | Upstream release commit |
|---|---|---|
| node-forge | 1.4.3 | 936b24d939dc7261ee37982576f9cf2b410084ee |
| @noble/hashes | 2.4.0 | 663c2aeeffc308ac0cded59bd32f7c212adacfc2 |
| esbuild | 0.28.2 | 609683d892977362a0f99026cb74b96263d728a9 |

The Noble browser imports are @noble/hashes/hkdf.js and
@noble/hashes/sha2.js. Inputs are Uint8Array values; TextEncoder, Buffer,
WebCrypto and Node crypto are not required inside the browser client.

Use a Linux x64 little-endian runner with Node >=20.19.0:

    npm install --ignore-scripts --include=optional --no-audit --no-fund
    node build-client.mjs
    node test-client.mjs

Run the commands from tools/examclips-recovery. The build script resolves paths
from its own directory, verifies installed versions and the exact optional
Linux x64 esbuild binary before executing it. It never runs npm lifecycle
scripts. Do not omit optional dependencies.

Verified upstream esbuild binary SHA256:

    e1698a3d5c6c0798fee4fd3b5cc816651f460c63d390a7a26ea4beb0b1884100

Outputs are client-bundle.js, client-bundle.meta.json and
client-bundle.manifest.json. The manifest records source, tool and bundle
provenance; building alone does not claim runtime tests passed.

## Runtime checks and scope

The IIFE exposes AuditCrypto. Forge uses self/global aliases to globalThis.
Math.random is disabled before dependency initialization; the entry point
also locks every exported Forge RNG path used by this implementation.
Public RSA-OAEP requires an explicit 32-byte seed, SHA256, MGF1-SHA256,
an explicit label and an RSA4096 public key with exponent65537.
AES256-GCM requires a 32-byte key, 12-byte IV, 16-byte tag and explicit AAD.
The decrypt helper returns plaintext only after authentication succeeds.

Loading the client executes SHA256("abc"), RFC5869 case1 and the official
Forge AES256-GCM known-answer vector. It also verifies rejection of altered
tags/AAD and forbidden RNG calls. test-client.mjs runs the bundle in a VM
without crypto, Buffer, TextEncoder, process or require. Public RSA-OAEP
interoperability with the controller remains a separate gate before any
private input.

At source preparation, syntax and upstream vector/API provenance were
checked. No claim of actual bundle execution is made until the runner and
functions V8 have executed it successfully.

## Primary provenance

- https://github.com/digitalbazaar/forge/tree/936b24d939dc7261ee37982576f9cf2b410084ee
- https://github.com/paulmillr/noble-hashes/tree/663c2aeeffc308ac0cded59bd32f7c212adacfc2
- https://github.com/evanw/esbuild/tree/609683d892977362a0f99026cb74b96263d728a9
- https://github.com/evanw/esbuild/blob/609683d892977362a0f99026cb74b96263d728a9/npm/esbuild/package.json
- https://github.com/digitalbazaar/forge/blob/936b24d939dc7261ee37982576f9cf2b410084ee/tests/unit/aes.js
- https://www.rfc-editor.org/rfc/rfc5869.html


## Strict session utility

client-session.mjs contains no imports and uses the already verified AuditCrypto
primitives in the same JavaScript realm. It requires Uint8Array.fromBase64 and
Uint8Array.prototype.toBase64 and never falls back to another entropy source.
The utility contains no private values, real grants or real reply keys.

- verifyDescriptor(C, descriptor, expected = {}, now = Date.now()) checks the
  fixed repository/branch, lane/run strings, key fingerprint, source commit and
  a live descriptor with at most a 46-minute declared lifetime.
- deriveMaterials(C, descriptor, entropy32) returns key (32 bytes), iv (12),
  oaepSeed (32), replyKey (32) and binding. HKDF-SHA256 uses distinct labels and
  binds repository, branch, run, attempt, lane, public-key hash and bundle hash.
- contextFor(descriptor, purpose, extra = {}) builds the exact controller
  context; review-reply requires extra = {sequence, key}, with key nullable.
- sealInput(C, descriptor, purpose, payload, materials) uses the existing
  AES-256-GCM+RSA-OAEP-SHA256 envelope, top-level canonical AAD, and empty OAEP
  label. Production payloads must contain the matching version, bundleSha256
  and base64 replyKey. One materials object may be sealed only once per loaded
  module. Persist and replay the original envelope; never reseal a changed
  payload with the same derived key/IV, including across fresh isolates.
- publicFixture(C, descriptor) returns envelope, replyKeyBase64 and
  expectedReplyContext. Its known key/IV/seed/reply key are exclusively for the
  fixed public interoperability payload and fixture purpose. They are not a
  production fallback.
- assembleReply(C, envelope, fetchedParts, expectedContext) accepts an array of
  {path, content} records containing exact fetched part JSON strings. It
  validates paths, indices, counts, fragment sizes and SHA256 before assembly.
  The result is still unauthenticated until decryptReply succeeds.
- decryptReply(C, envelope, replyKey, expectedContext) verifies the exact
  context and limits, authenticates GCM using the unchanged envelope.context,
  checks plaintext size/SHA256, decodes strict UTF-8, parses JSON and verifies
  every returned file record. Reply plaintext is capped at 20 MiB.
- verifyRecord(C, record), verifyFileRecords(C, records),
  verifiedText(C, record) and imageDataUrl(C, record) check raw file byte counts
  and SHA256 before returning bytes/text or an image URL. Images also require
  the corresponding PNG/JPEG signature. Individual files are capped at 8 MiB;
  a packet is capped at 12 MiB and 12 distinct paths.
- parseGrants(transferA, transferB, expectedA, expectedB, now = Date.now())
  requires different exact Library IDs and distinct blob resources/signatures,
  HTTPS Azure blob hosts or official sdmntpr*.oaiusercontent.com Library hosts,
  sr=b, sp=r, user-delegation fields, no extra headers,
  live grants, and canonical 32-byte decoded signatures. It returns the full
  unchanged A transfer, entropy32 from B, and expiry times. The caller must keep
  B private and unused and must never print or transmit B or entropy32.
- canonical, fromBase64, toBase64 and utf8Text provide strict conversion helpers.
  canonical intentionally sorts only top-level keys, matching the Node bridge.

To load the session module in a functions V8 isolate, verify the source bytes
against the reviewed Git blob/content hash, remove its final explicit export
block, and evaluate the remaining declarations with an appended return object
listing those exports. Load the verified crypto bundle once in that same
isolate. Do not expose native crypto/process/network globals. Store private
session values privately; never include them in log calls.

test-client.mjs also imports test-client-session.mjs. The latter generates a
disposable public-test RSA4096 keypair in Node, runs crypto and session code in
one isolated VM, and tests Node interoperability, independent HKDF agreement,
descriptor expiry/fingerprint, nested-context AAD, corrupt replies, file
integrity, strict UTF-8, multipart bounds and synthetic SAS guard failures.
The private component of this disposable fixture keypair stays in test memory.
No actual recovery key or materialization grant is used.

Publishing these sources does not establish that the new runtime tests passed;
the next authorized runner must complete them before private handoff.
