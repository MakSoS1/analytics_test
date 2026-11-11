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
