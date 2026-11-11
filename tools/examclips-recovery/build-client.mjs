import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { endianness } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const expectedBinarySha256 =
  'e1698a3d5c6c0798fee4fd3b5cc816651f460c63d390a7a26ea4beb0b1884100';
const expectedVersions = {
  'node-forge': '1.4.3',
  '@noble/hashes': '2.4.0',
  esbuild: '0.28.2',
  '@esbuild/linux-x64': '0.28.2'
};
const sha = value => createHash('sha256').update(value).digest('hex');
const json = async path => JSON.parse(await readFile(path, 'utf8'));

if (process.platform !== 'linux' || process.arch !== 'x64' || endianness() !== 'LE') {
  throw new Error('VERIFIED_LINUX_X64_RUNNER_REQUIRED');
}
const nodeParts = process.versions.node.split('.').map(Number);
if (nodeParts[0] < 20 || (nodeParts[0] === 20 && nodeParts[1] < 19)) {
  throw new Error('NODE_20_19_OR_NEWER_REQUIRED');
}

const installedPackages = {
  'node-forge': require.resolve('node-forge/package.json'),
  '@noble/hashes': join(dirname(require.resolve('@noble/hashes/hkdf.js')), 'package.json'),
  esbuild: require.resolve('esbuild/package.json'),
  '@esbuild/linux-x64': require.resolve('@esbuild/linux-x64/package.json')
};
for (const [name, packagePath] of Object.entries(installedPackages)) {
  const metadata = await json(packagePath);
  if (metadata.name !== name || metadata.version !== expectedVersions[name]) {
    throw new Error('PINNED_DEPENDENCY_VERSION_MISMATCH');
  }
}

const binary = require.resolve('@esbuild/linux-x64/bin/esbuild');
const binarySha256 = sha(await readFile(binary));
if (binarySha256 !== expectedBinarySha256) {
  throw new Error('ESBUILD_BINARY_SHA256_MISMATCH');
}
const version = spawnSync(binary, ['--version'], {
  encoding: 'utf8',
  timeout: 30000
});
if (version.error || version.status !== 0 || version.stdout.trim() !== '0.28.2') {
  throw new Error('ESBUILD_BINARY_VERSION_MISMATCH');
}

const output = join(here, 'client-bundle.js');
const metafile = join(here, 'client-bundle.meta.json');
const args = [
  join(here, 'client.mjs'),
  '--bundle',
  '--platform=browser',
  '--format=iife',
  '--global-name=AuditCrypto',
  '--target=es2022',
  '--minify',
  '--legal-comments=inline',
  '--define:self=globalThis',
  '--define:global=globalThis',
  '--banner:js=Math.random = function () { throw new Error("RNG_FORBIDDEN_AT_LOAD"); };',
  '--outfile=' + output,
  '--metafile=' + metafile
];
const built = spawnSync(binary, args, {
  cwd: here,
  encoding: 'utf8',
  timeout: 120000,
  maxBuffer: 8 * 1024 * 1024
});
if (built.error || built.status !== 0) {
  if (built.stderr) process.stderr.write(built.stderr);
  throw new Error('PUBLIC_CLIENT_BUILD_FAILED');
}

const bundle = await readFile(output);
const manifest = {
  schema: 1,
  publicCodeOnly: true,
  versions: expectedVersions,
  upstreamCommits: {
    forge: '936b24d939dc7261ee37982576f9cf2b410084ee',
    nobleHashes: '663c2aeeffc308ac0cded59bd32f7c212adacfc2',
    esbuild: '609683d892977362a0f99026cb74b96263d728a9'
  },
  esbuildBinarySha256: binarySha256,
  inputSha256: sha(await readFile(join(here, 'client.mjs'))),
  buildScriptSha256: sha(await readFile(fileURLToPath(import.meta.url))),
  bundleFile: 'client-bundle.js',
  bundleBytes: bundle.length,
  bundleSha256: sha(bundle),
  metafileSha256: sha(await readFile(metafile)),
  runtimeTestsExecutedByThisBuild: false
};
await writeFile(
  join(here, 'client-bundle.manifest.json'),
  JSON.stringify(manifest, null, 2) + '\n'
);
console.log(JSON.stringify(manifest));
