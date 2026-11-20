/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

function runCorpus() {
  const calls = {};
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const addon = require('../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');
    for (const name of ['publicKeyCreate', 'derivePrivatePath', 'derivePublicPath']) {
      const implementation = addon[name];
      assert.equal(typeof implementation, 'function', 'Rebuild the addon to test ' + name);
      calls[name] = 0;
      addon[name] = (...args) => {
        calls[name]++;
        return implementation(...args);
      };
    }
  }
  const { HDPrivateKey, HDPublicKey, PrivateKey, Networks, crypto: { BN, Hash } } =
    require('../packages/bitcore-lib');
  const results = [];
  for (let i = 0; i < 24; i++) {
    const seed = Hash.sha256(Buffer.from('HD differential fixture ' + i));
    const network = i % 2 ? Networks.testnet : Networks.livenet;
    const key = new PrivateKey(i % 2 ? seed : BN.fromBuffer(seed), network);
    const pub = key.toPublicKey();
    assert.equal(pub.network, key.network);
    assert.equal(pub.compressed, key.compressed);
    assert.equal(pub, key.toPublicKey());
    results.push(pub.toString(), pub.toAddress().toString());
    const root = HDPrivateKey.fromSeed(seed, network);
    const watch = new HDPublicKey(root.xpubkey);
    assert.equal(root.deriveChild('m'), root);
    assert.equal(watch.deriveChild('M'), watch);
    const ordinary = 'm/0/' + i + '/2147483647';
    const mixed = "m/84'/0'/1'/0/" + i;
    const child = root.deriveChild(ordinary);
    assert.equal(child.xpubkey, watch.deriveChild(ordinary).xpubkey);
    const mixedKey = root.deriveChild(mixed);
    assert.equal(mixedKey.xprivkey, root.deriveChild(84, true).deriveChild(0, true)
      .deriveChild(1, true).deriveChild(0).deriveChild(i).xprivkey);
    results.push(child.xprivkey, child.xpubkey, mixedKey.xprivkey, mixedKey.xpubkey,
      watch.deriveChild(2147483647).toObject(), root.deriveChild(0xffffffff).toObject());
  }

  // A small parent scalar distinguishes the historic unpadded hardened key
  // encoding from BIP32. Start near depth 255 to exercise byte rollover.
  const leadingZero = new HDPrivateKey({ network: 'livenet', depth: 254,
    parentFingerPrint: 0, childIndex: 0, chainCode: Buffer.alloc(32, 1),
    privateKey: BN.One.toBuffer({ size: 32 }) });
  const path = "m/0'/1/2'";
  const legacy = leadingZero.deriveNonCompliantChild(path);
  assert.equal(legacy.xprivkey, leadingZero.derive(path).xprivkey);
  assert.notEqual(legacy.xprivkey, leadingZero.deriveChild(path).xprivkey);
  results.push(legacy.toObject(), leadingZero.deriveChild(path).toObject());
  for (const parent of [leadingZero, leadingZero.hdPublicKey]) {
    parent.fingerPrint.fill(0x56);
    const child = parent.deriveChild(7);
    assert.equal(child.toObject().parentFingerPrint, 0x56565656);
    results.push(child.toString(), parent.deriveChild(1.5).toString());
  }
  const modified = HDPrivateKey.fromSeed(Buffer.alloc(32, 12));
  modified.privateKey.bn.iaddn(1);
  results.push(modified.deriveChild('m/0/1').xprivkey);
  const sharedCode = Buffer.from(new SharedArrayBuffer(32));
  sharedCode.fill(7);
  const shared = new HDPrivateKey({ network: 'livenet', depth: 0,
    parentFingerPrint: 0, childIndex: 0, chainCode: sharedCode,
    privateKey: BN.One.toBuffer({ size: 32 }) });
  results.push(shared.deriveChild(1).xprivkey, shared.hdPublicKey.deriveChild(2).xpubkey);
  results.push(leadingZero.deriveChild(5, 1).xprivkey,
    leadingZero.deriveChild('m' + '/1'.repeat(256)).xprivkey);
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const addon = require('../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');
    for (const [parent, method] of [[leadingZero, 'derivePrivatePath'], [leadingZero.hdPublicKey, 'derivePublicPath']]) {
      const original = addon[method];
      const expected = parent.deriveChild('m/3/19').toString();
      try {
        addon[method] = () => null;
        assert.equal(parent.deriveChild('m/3/19').toString(), expected);
        addon[method] = () => Buffer.alloc(1);
        assert.throws(() => parent.deriveChild(7), /Invalid result/);
      } finally {
        addon[method] = original;
      }
    }
    const loader = require.resolve('../packages/bitcore-lib/lib/crypto/ecdsa-native');
    const version = addon.abiVersion;
    addon.abiVersion = 99;
    delete require.cache[loader];
    try {
      assert.throws(() => require(loader), /Incompatible Bitcore addon ABI/);
    } finally {
      addon.abiVersion = version;
    }
  }
  for (const derive of [
    () => leadingZero.deriveChild(0x100000000),
    () => leadingZero.hdPublicKey.deriveChild("m/0'"),
    () => leadingZero.deriveChild('m//9')
  ]) {
    assert.throws(derive, error => {
      results.push([error.name, error.message]);
      return true;
    });
  }
  // Compare a digest of the entire corpus so a mismatch cannot dump private
  // fixture values into CI output.
  for (const [name, count] of Object.entries(calls)) {
    assert(count > 0, 'Public API did not exercise ' + name);
  }
  return Hash.sha256(Buffer.from(JSON.stringify(results))).toString('hex');
}

if (process.argv[2] === '--corpus') {
  process.stdout.write(runCorpus());
} else {
  const run = backend => execFileSync(process.execPath, [__filename, '--corpus'], {
    env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
  });
  assert.equal(run('native'), run('js'));
  console.log('Public keys and HD derivation matched across both backends.');
}
