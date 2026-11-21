/* eslint @typescript-eslint/no-require-imports: "off" -- Offline native/JS parity corpus. */
'use strict';

const assert = require('node:assert/strict');
const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');

function replace(obj, method, replacement, run) {
  const original = obj[method];
  try {
    obj[method] = replacement;
    return run();
  } finally {
    obj[method] = original;
  }
}

// Counters are local to a worker. In particular, elliptic's shared Point prototype
// cannot redirect one coin's test into another coin's implementation.
function coinCases(coin, backend) {
  const pkg = '../packages/' + coin;
  const { native } = require(pkg + '/lib/crypto/ecdsa-native');
  assert.equal(Boolean(native), backend === 'native');
  const calls = {};
  if (native) {
    for (const name of ['sign', 'verify', 'recover', 'publicKeyParse', 'derivePrivatePath', 'derivePublicPath']) {
      const original = native[name];
      calls[name] = 0;
      native[name] = (...args) => {
        const result = original(...args);
        if (result) calls[name]++;
        return result;
      };
    }
  }
  const { HDPrivateKey, PrivateKey, PublicKey, crypto: { BN, ECDSA, Hash, Point, Signature } } = require(pkg);
  const key = new PrivateKey(BN.One);
  const order = Point.getN();
  const message = Buffer.alloc(32, 3);
  const sig = ECDSA.sign(message, key);
  assert(ECDSA.verify(message, sig, key.publicKey));
  ECDSA.calci(message, sig, key.publicKey);
  assert.equal(ECDSA.recoverPublicKey(message, sig).toString(), key.publicKey.toString());
  const raw = key.publicKey.toBuffer();
  assert.equal(PublicKey.fromDER(raw).toString(), key.publicKey.toString());
  const uncompressed = Buffer.from(Point.getG().encode('array', false));
  for (const prefix of [4, 6, 7]) {
    const sec = Buffer.from(uncompressed);
    sec[0] = prefix;
    assert.equal(PublicKey.fromDER(sec, false).point.eq(key.publicKey.point), true);
  }
  for (const length of [1, 33, 64, 66]) {
    const sec = Buffer.alloc(length, 4);
    assert.throws(() => PublicKey.fromDER(sec), /Length of x and y/);
  }
  assert.throws(() => PublicKey.fromDER(Buffer.from([5])), /Invalid DER format public key/);

  const g = Point.getG();
  const checked = Point(g.getX(), g.getY());
  // Custom multiplication must still be consulted by the legacy subgroup check.
  replace(checked, 'mul', () => g, () =>
    assert.throws(() => checked.validate(), /Point times N must be infinity/));
  assert.equal(checked.validate(), checked);
  assert.throws(() => Point('0', '1'), /Point does not lie on the curve/);
  assert.throws(() => Point(g.getX(), '1'), /Invalid y value for curve/);

  const infinityDigest = order.subn(1).toBuffer({ size: 32 });
  const infinitySig = new Signature(BN.One, BN.One);
  assert.equal(ECDSA.verificationError(infinityDigest, infinitySig, key.publicKey), 'p is infinity');
  const recovered = [];
  for (const i of [2, 3]) {
    const secondKey = new Signature(new BN(2), BN.One);
    secondKey.i = i;
    const candidate = ECDSA.recoverPublicKey(message, secondKey);
    assert(ECDSA.verify(message, secondKey, candidate));
    recovered.push(candidate.toString());
  }

  // The subgroup guard is normally unreachable for a valid secp256k1 point.
  // A short digest selects legacy recovery in both modes, where Point is overridable.
  replace(Point, 'fromX', () => ({ mul: () => ({ isInfinity: () => false }) }), () =>
    assert.throws(() => ECDSA.recoverPublicKey(message.subarray(1), sig), /nR is not a valid curve point/));
  // A short digest uses the public recovery implementation even with the addon
  // loaded. The failure for each candidate is observable via console.error.
  const failures = [];
  replace(Point, 'fromX', () => { throw new Error('unavailable candidate'); }, () =>
    replace(console, 'error', error => failures.push(error.message), () =>
      assert.throws(() => ECDSA.calci(message.subarray(1), sig, key.publicKey), /Unable to find valid recovery factor/)));
  assert.deepEqual(failures, Array(4).fill('unavailable candidate'));

  const root = HDPrivateKey.fromSeed(Buffer.alloc(32, 42));
  const child = root.deriveChild(21);
  const publicRoot = root.hdPublicKey;
  assert.equal(child.hdPublicKey.toString(), publicRoot.deriveChild(21).toString());

  // IL = -parent (mod n) produces a zero private child or an infinite public
  // child. Inject only that first digest, then use the real HMAC for index + 1.
  const first = order.sub(root.privateKey.bn).toBuffer({ size: 32 });
  const hmac = Hash.sha512hmac;
  for (const parent of [root, publicRoot]) {
    const seen = [];
    const retried = replace(Hash, 'sha512hmac', (data, chainCode) => {
      const index = data.readUInt32BE(data.length - 4);
      seen.push(index);
      return index === 17 ? Buffer.concat([first, chainCode]) : hmac(data, chainCode);
    }, () => parent.deriveChild(17));
    assert.deepEqual(seen, [17, 18]);
    assert.equal(retried.toString(), parent.deriveChild(18).toString());
  }

  if (coin === 'bitcore-lib') {
    const { Schnorr } = require(pkg).crypto;
    const TaggedHash = require(pkg + '/lib/crypto/taggedhash');
    // Force the astronomically rare zero BIP340 nonce. A replaced hash provider
    // is deliberately a fallback, so both selectors must preserve the same error.
    replace(TaggedHash.prototype, 'finalize', () => Buffer.alloc(32), () =>
      assert.throws(() => Schnorr.sign(key, message, Buffer.alloc(32)), /^Error: Error creating schnorr signature$/));
    const invalidLift = Object.create(Point.prototype);
    invalidLift.x = BN.Zero;
    assert.throws(() => invalidLift.liftX(), /liftX failed/);
    const ordinaryX = g.getX();
    const lifted = Point.prototype.liftX.call({ x: ordinaryX });
    assert.equal(lifted.x, ordinaryX);
    assert(lifted.eq(g));
  }
  if (coin === 'bitcore-lib-cash') {
    const { Schnorr } = require(pkg).crypto;
    const schnorr = new Schnorr();
    const signature = Schnorr.sign(message, key);
    schnorr.set({ hashbuf: message, pubkey: key.publicKey, sig: signature });
    const tooLong = BN.One.ushln(264);
    assert.equal(schnorr.set({ sig: new Signature(tooLong, BN.One) }).sigError(),
      'signature must be a 64 byte or 65 byte array');
    assert.equal(schnorr.set({ sig: signature, pubkey: { point: Point.getG().mul(BN.Zero) } }).sigError(), true);
    assert.equal(schnorr.set({ hashbuf: Buffer.alloc(31) }).sigError(), 'hashbuf must be a 32 byte buffer');
    assert.equal(g.isSquare(BN.Zero), false);
    assert.equal(g.isSquare(new BN(g.curve.p.toArray()).addn(1)), true);

    // Reject zero and n before accepting 1 from the BCH nonce generator.
    // Calls 5, 7 and 9 to sha256hmac are candidates; the retry also calls Hash.hmac directly.
    let count = 0;
    const candidates = [BN.Zero, order, BN.One];
    const sha256hmac = Hash.sha256hmac;
    replace(Hash, 'sha256hmac', (...args) => {
      count++;
      if ([5, 7, 9].includes(count)) return candidates.shift().toBuffer({ size: 32 });
      return sha256hmac(...args);
    }, () => assert.equal(schnorr.nonceFunctionRFC6979(key.toBuffer(), message).toString(), '1'));
    assert.equal(candidates.length, 0);
  }
  for (const [name, count] of Object.entries(calls)) assert(count > 0, coin + ' did not dispatch ' + name);
  return [sig.toString(), sig.i, recovered, child.toString()];
}

function run(coin, backend) {
  const env = { ...process.env, BITCORE_ECDSA_BACKEND: backend };
  for (const suffix of ['BCH', 'DOGE', 'LTC']) env['BITCORE_' + suffix + '_BACKEND'] = backend;
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { env, workerData: { coin, backend } });
    let result;
    worker.on('error', reject);
    worker.on('message', value => { result = value; });
    worker.on('exit', code => {
      if (code || !result) reject(new Error(coin + ' ' + backend + ' worker failed, code ' + code));
      else resolve(result);
    });
  });
}

async function main() {
  const selected = process.argv.includes('--selected') ? process.env.BITCORE_ECDSA_BACKEND : undefined;
  if (process.argv.includes('--selected')) assert.ok(selected === 'js' || selected === 'native');
  const results = [];
  for (const coin of ['bitcore-lib', 'bitcore-lib-cash', 'bitcore-lib-ltc', 'bitcore-lib-doge']) {
    if (selected) results.push(await run(coin, selected));
    else assert.deepEqual(await run(coin, 'native'), await run(coin, 'js'), coin);
  }
  if (selected) process.stdout.write(JSON.stringify(results));
  else console.log('Curve boundary and retry cases passed for all four coin libraries.');
}

if (isMainThread) {
  main().catch(error => { console.error(error); process.exitCode = 1; });
} else {
  parentPort.postMessage(coinCases(workerData.coin, workerData.backend));
}
