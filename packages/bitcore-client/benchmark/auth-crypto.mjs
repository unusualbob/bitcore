// Run from a workspace install with node packages/bitcore-client/benchmark/auth-crypto.mjs.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const packageRequire = name => createRequire(new URL(`../../${name}/package.json`, import.meta.url));
const clientRequire = packageRequire('bitcore-client');
const nodeRequire = packageRequire('bitcore-node');
const bwsRequire = packageRequire('bitcore-wallet-service');
const walletRequire = createRequire(clientRequire.resolve('@bitpay-labs/crypto-wallet-core'));
const bitcore = walletRequire('@bitpay-labs/bitcore-lib');
const { native } = walletRequire('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
const sjcl = bwsRequire('sjcl');

function loadSecp(name, load) {
  const secp = load('secp256k1');
  const backend = secp === load(path.join(path.dirname(load.resolve('secp256k1')), 'elliptic.js')) ? 'elliptic JS' : 'native';
  console.log(`${name}: secp256k1 ${load('secp256k1/package.json').version} (${backend})`);
  return secp;
}

console.log(`Node ${process.version}, ${process.platform}/${process.arch}, Bitcore native ABI ${native?.abiVersion ?? 'unavailable'}`);
const clientSecp = loadSecp('bitcore-client', clientRequire);
const nodeSecp = loadSecp('bitcore-node', nodeRequire);
const bwsSecp = loadSecp('bitcore-wallet-service', bwsRequire);
assert.ok(native, 'The auth comparison requires the optional Bitcore addon');

const privateKey = new bitcore.PrivateKey('00'.repeat(31) + '01');
const publicKey = privateKey.toPublicKey().toBuffer();
const publicKeyHex = publicKey.toString('hex');
const { sha256sha256 } = bitcore.crypto.Hash;
const fixtures = Array.from({ length: 128 }, (_, i) => {
  const url = `https://example.test/api/BTC/mainnet/wallet/${publicKeyHex}?page=${i}`;
  const payload = [{ address: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', index: i }];
  const { pathname, search } = new URL(url);
  const message = ['POST', pathname + search, JSON.stringify(payload)].join('|');
  const digest = sha256sha256(Buffer.from(message));
  const compact = clientSecp.sign(digest, privateKey.toBuffer()).signature;
  assert.deepEqual(native.sign(digest, privateKey.toBuffer()), compact);
  assert.deepEqual(Buffer.from(bwsSecp.ecdsaSign(digest, privateKey.toBuffer()).signature), compact);
  const derHex = Buffer.from(bwsSecp.signatureExport(compact)).toString('hex');
  return { url, payload, message, compactHex: compact.toString('hex'), derHex };
});

function signRequest(sign, { url, payload }, key = () => privateKey.toBuffer()) {
  const { pathname, search } = new URL(url);
  const message = ['POST', pathname + search, JSON.stringify(payload)].join('|');
  const signature = sign(sha256sha256(Buffer.from(message)), key());
  return (Buffer.isBuffer(signature) ? signature : Buffer.from(signature)).toString('hex');
}

const halfOrder = Buffer.from('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 'hex');
function verifyNative(compact, digest, key) {
  // Compare valid input throughput with the low-S check that v4 enforces.
  // Error handling for malformed input remains in the existing v4 routes.
  const signature = Buffer.isBuffer(compact) ? compact : Buffer.from(compact);
  return Buffer.compare(signature.subarray(32), halfOrder) <= 0 && native.verify(digest, signature, key);
}

function verifyRequest(verify, { message, compactHex }) {
  const key = new bitcore.PublicKey(publicKeyHex).toBuffer();
  const digest = sha256sha256(Buffer.from(message));
  return verify(Buffer.from(compactHex, 'hex'), digest, key);
}

function verifyDer(verify, { message, derHex }) {
  const digest = sha256sha256(Buffer.from(message));
  const signature = bwsSecp.signatureImport(Buffer.from(derHex, 'hex'));
  return verify(signature, digest, Buffer.from(publicKeyHex, 'hex'));
}

function measure(label, operation, iterations = 8192) {
  for (const fixture of fixtures) assert.ok(operation(fixture));
  for (let i = 0; i < 1024; i++) operation(fixtures[i % fixtures.length]);
  const samples = Array.from({ length: 5 }, () => {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) operation(fixtures[i % fixtures.length]);
    return (performance.now() - start) * 1000 / iterations;
  }).sort((a, b) => a - b);
  console.log(`${label.padEnd(45)} ${samples[2].toFixed(2)} µs/op (median of 5 × ${iterations})`);
}

const signV3 = (digest, key) => clientSecp.sign(digest, key).signature;
const signV4 = (digest, key) => bwsSecp.ecdsaSign(digest, key).signature;
const signWithAddon = (digest, key) => {
  const compact = Buffer.isBuffer(key) && key.length === 32 ? native.sign(digest, key) : undefined;
  return compact ?? signV3(digest, key);
};
measure('Client sign, v3 installed', fixture => signRequest(signV3, fixture), 2048);
measure('Client sign, Bitcore addon', fixture => signRequest(signWithAddon, fixture));
measure('V8 sign, v4 installed', fixture => signRequest(signV4, fixture, () => privateKey.bn.toBuffer({ size: 32 })));
measure('Node compact verify, v4 installed', fixture => verifyRequest(nodeSecp.ecdsaVerify, fixture));
measure('Node compact verify, Bitcore addon + low S', fixture => verifyRequest(verifyNative, fixture));
measure('BWS DER verify, v4 installed', fixture => verifyDer(bwsSecp.ecdsaVerify, fixture));
measure('BWS DER verify, Bitcore addon + low S', fixture => verifyDer(verifyNative, fixture));

const xpub = 'xpub661MyMwAqRbcFLRkhYzK8eQdoywNHJVsJCMQNDoMks5bZymuMcyDgYfnVQYq2Q9npnVmdTAthYGc3N3uxm5sEdnTpSqBc4YYTAhNnoSxCm9';
const walletId = '641f8579-270e-400e-94ee-94dbfab4db41';
const copayerId = '77a8752fdddbe10fb9c290bd55ea8efbb1ad72adb4e68e8b57bf04adc3cc3ebb';
const sjclHash = value => sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(value));
const streamingHash = value => crypto.createHash('sha256').update(value).digest('hex');
const identifierHash = value => {
  if (typeof value !== 'string' || /[\uD800-\uDFFF]/.test(value)) return sjclHash(value);
  return crypto.hash?.('sha256', value, 'hex') ?? streamingHash(value);
};
for (const value of [xpub, walletId, copayerId]) {
  assert.equal(identifierHash(value), sjclHash(value));
  assert.equal(streamingHash(value), sjclHash(value));
}
measure('Copayer xpub hash, SJCL', () => sjclHash(xpub), 32768);
measure('Copayer xpub hash, Node', () => identifierHash(xpub), 32768);
measure('Copayer xpub hash, Node createHash', () => streamingHash(xpub), 32768);
measure('Push IDs (both hashes), SJCL', () => [sjclHash(walletId), sjclHash(copayerId)], 32768);
measure('Push IDs (both hashes), Node', () => [identifierHash(walletId), identifierHash(copayerId)], 32768);
measure('Push IDs (both hashes), Node createHash', () => [streamingHash(walletId), streamingHash(copayerId)], 32768);
