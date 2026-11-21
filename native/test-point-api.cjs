/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS script. */
'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createRequire } = require('node:module');
const { Worker, parentPort } = require('node:worker_threads');

function modPow(base, exponent, modulus) {
  let result = 1n;
  for (; exponent > 0n; exponent /= 2n) {
    if (exponent % 2n !== 0n) result = result * base % modulus;
    base = base * base % modulus;
  }
  return result;
}

function hash(label, index) {
  return createHash('sha256').update(`${label}-${index}`).digest('hex');
}

function checkLibrary({ name, Point, BN, ec, ellipticMul, ellipticAdd, bnMul, bnDiv, bnRedPow, calls }) {
  const g = Point.getG();
  const field = g.curve.p;
  const p = BigInt('0x' + field.toString(16));
  const n = Point.getN();
  const infinity = g.curve.point(null, null);
  assert.equal(Point.prototype, Object.getPrototypeOf(ec.g));
  assert.equal(Point.prototype.mul, ellipticMul);
  assert.equal(Point.prototype.add, ellipticAdd);
  assert.equal(BN.prototype.mul, bnMul);
  assert.equal(BN.prototype.div, bnDiv);
  assert.equal(BN.prototype.redPow, bnRedPow);
  const record = point => Point.pointToCompressed(point).toString('hex');

  const results = [];
  for (let i = 0; i < 16; i++) {
    const k = new BN(hash(name, i), 16);
    const expected = g.mul(k);
    const x = expected.getX();
    const y = expected.getY();
    const xy = Point(x, y);
    assert.equal(xy.validate(), xy);
    assert.equal(Object.getPrototypeOf(xy), Point.prototype);
    assert.equal(Object.getPrototypeOf(xy.getX()), BN.prototype);
    assert.equal(Object.getPrototypeOf(xy.x), BN.prototype);
    assert.equal(Object.getPrototypeOf(Point(x.toString(16), y.toString(16)).x), Object.getPrototypeOf(g.x));

    const before = calls?.count;
    for (const input of [x, x.toString(16)]) {
      for (const odd of [false, true]) {
        const actual = Point.fromX(odd, input);
        const legacy = g.curve.pointFromX(input, odd);
        assert.equal(record(actual), record(legacy));
        assert.equal(Object.getPrototypeOf(actual.x), Object.getPrototypeOf(legacy.x));
        assert.equal(Object.getPrototypeOf(actual.y), Object.getPrototypeOf(legacy.y));
        results.push(record(actual));
      }
    }
    if (calls) assert.equal(calls.count, before + 4, name + ' compressed SEC dispatch');
    const redX = expected.x;
    assert.equal(Point.fromX(y.isOdd(), redX).x, redX);
    assert.equal(record(Point.fromX(y.isOdd(), x.add(field))), record(expected));
    assert.equal(record(Point.fromX(y.isOdd() ? 1 : 0, x.toArray())), record(expected));
    assert.equal(record(Point(x.add(field), y.add(field))), record(expected));
    const forcedX = x.clone();
    const forcedY = y.clone();
    const forced = new Point(forcedX, forcedY, true);
    assert.equal(forced.x, forcedX);
    assert.equal(forced.y, forcedY);
    assert.equal(record(forced), record(expected));
    if (calls) assert.equal(calls.count, before + 4, name + ' compatibility dispatch');

    assert.equal(infinity.add(xy), xy);
    assert.equal(xy.add(infinity), xy);
    assert.equal(infinity.mul(k), infinity);
    assert(xy.add(xy.neg()).isInfinity());
    assert(xy.mul(new BN(0)).isInfinity());
    assert(xy.mul(n).isInfinity());
    assert(xy.mul(n.addn(1)).eq(xy));
    assert(xy.mul(new BN(-1)).eq(xy.neg()));
    assert(xy.add(g).eq(g.mul(k.addn(1))));

    if (name === 'bitcore-lib') {
      const beforeLift = calls?.count;
      for (const input of [xy, expected, xy.neg()]) {
        const lifted = input.liftX();
        assert.equal(lifted.getX().cmp(x), 0);
        assert(lifted.getY().isEven());
        assert.equal(lifted.validate(), lifted);
        assert.notEqual(lifted.x, input.x);
        assert.equal(Object.getPrototypeOf(lifted.x), Object.getPrototypeOf(input.x));
        results.push([record(lifted), Object.getPrototypeOf(lifted.y) === BN.prototype]);
      }
      if (calls) assert.equal(calls.count, beforeLift + 3);
    }
    if (name === 'bitcore-lib-cash') {
      const square = y0 => modPow(BigInt(y0.toString(10)) % p, (p - 1n) / 2n, p) === 1n;
      assert.equal(xy.hasSquare(), square(y));
      assert.equal(xy.isSquare(x), square(x));
      assert.equal(xy.isSquare(new BN((p + 1n).toString())), true);
      assert.equal(xy.isSquare(new BN(p.toString())), false);
      assert.equal(xy.isSquare(new BN(0)), false);
      assert.throws(() => xy.isSquare(new BN(-1)), /works only with positives/);
      assert.throws(() => xy.isSquare(y.toRed(BN.red('k256'))), /Already a number in reduction context/);
      assert.equal(infinity.hasSquare(), false);
    }
  }

  assert.throws(() => Point(null, null), /Point cannot be equal to Infinity/);
  assert.throws(() => Point('-', '1'), /Invalid Point|Point does not lie on the curve/);
  assert.throws(() => Point('0', '1'), /^Error: Point does not lie on the curve$/);
  assert.throws(() => Point(g.getX(), '1'), /^Error: Invalid y value for curve\.$/);
  assert.throws(() => Point.fromX(false, '0'), /^Error: Invalid X$/);
  assert.throws(() => Point.fromX(true, new BN(-1)), /^Error: Invalid X$/);
  assert.throws(() => infinity.validate(), /Point cannot be equal to Infinity/);
  assert.throws(() => new ec.constructor('p256').g.validate(), /Point does not lie on the curve|Invalid y value/);

  const changed = Point(g.getX(), g.getY());
  changed.y.iaddn(1);
  assert.throws(() => changed.validate(), /Invalid y value for curve/);

  const customX = g.getX();
  const toRed = customX.toRed;
  let converted = 0;
  customX.toRed = function(context) {
    converted++;
    return toRed.call(this, context);
  };
  const before = calls?.count;
  Point.fromX(false, customX);
  assert.equal(converted, 1);
  assert.equal(calls?.count, before);

  if (name === 'bitcore-lib') {
    const altered = Point(g.getX(), g.getY());
    let powered = 0;
    altered.x.pow = function(exponent) {
      powered++;
      return BN.prototype.pow.call(this, exponent);
    };
    assert(altered.liftX().eq(g));
    assert.equal(powered, 1);
    assert.equal(calls?.count, before);
    delete altered.x.pow;
    altered.x.words = [0];
    altered.x.length = 1;
    assert.throws(() => altered.liftX(), /^Error: liftX failed$/);
    if (calls) assert.equal(calls.count, before + 1);
  }

  return results;
}

function checkOverrides(Point) {
  const g = Point.getG();
  const x = g.getX();
  const y = g.getY();
  const point = Point(x, y);
  point.getX = () => x;
  point.getY = () => y.addn(1);
  assert.throws(() => point.validate(), /^Error: Invalid y value for curve\.$/);
  delete point.getX;
  delete point.getY;
  point.mul = () => g;
  assert.throws(() => point.validate(), /^Error: Point times N must be infinity$/);
  delete point.mul;
  const overrides = [
    [Point, 'getN', () => x],
    [Point.prototype, 'mul', () => g],
    [g.curve, '_endoWnafMulAdd', () => g]
  ];
  for (const [target, method, override] of overrides) {
    const descriptor = Object.getOwnPropertyDescriptor(target, method);
    target[method] = override;
    try {
      assert.throws(() => point.validate(), /^Error: Point times N must be infinity$/);
    } finally {
      if (descriptor) Object.defineProperty(target, method, descriptor);
      else delete target[method];
    }
  }
  const mul = Object.getOwnPropertyDescriptor(Point.prototype, 'mul');
  let mulReads = 0;
  Object.defineProperty(Point.prototype, 'mul', {
    configurable: true,
    get() {
      mulReads++;
      return () => g;
    }
  });
  try {
    assert.throws(() => point.validate(), /^Error: Point times N must be infinity$/);
    assert.equal(mulReads, 1);
  } finally {
    Object.defineProperty(Point.prototype, 'mul', mul);
  }
  const validate = Point.prototype.validate;
  let validated = 0;
  Point.prototype.validate = function() {
    validated++;
    return this;
  };
  try {
    Point(x, y);
    Point.fromX(false, x);
    assert.equal(validated, 2);
  } finally {
    Point.prototype.validate = validate;
  }
}

function checkLargeBN(BN) {
  const hex = label => Array.from({ length: 16 }, (_, index) => hash(label, index)).join('');
  const a = new BN('-' + hex('a'), 16);
  const b = new BN(hex('b'), 16);
  const divisor = new BN(hash('divisor', 0), 16);
  const big = value => BigInt(value.toString(10));
  assert.equal(big(a.mul(b)), big(a) * big(b));
  assert.equal(big(a.div(divisor)), big(a) / big(divisor));
  assert.equal(big(a.mod(divisor)), big(a) % big(divisor));
  const red = BN.red('k256');
  const base = divisor.toRed(red);
  const exponent = new BN(hash('exponent', 0), 16);
  const result = base.redPow(exponent);
  assert.equal(result.red, red);
  assert.equal(big(result.fromRed()), modPow(big(divisor), big(exponent), big(red.m)));
}

function runCorpus() {
  const libraries = ['', '-cash', '-ltc', '-doge'].map(suffix => {
    const name = 'bitcore-lib' + suffix;
    const local = createRequire(require.resolve(`../packages/${name}`));
    const ec = new (local('elliptic').ec)('secp256k1');
    const { mul: ellipticMul, add: ellipticAdd } = Object.getPrototypeOf(ec.g);
    const curveProperties = Reflect.ownKeys(ec.curve);
    const generatorProperties = Reflect.ownKeys(ec.g);
    const fixedNafMul = ec.curve._fixedNafMul;
    const originalBN = local('bn.js');
    const { mul: bnMul, div: bnDiv, redPow: bnRedPow } = originalBN.prototype;
    let calls;
    if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
      const addon = local('./lib/native/bitcore_ecdsa.node');
      const parse = addon.publicKeyParse;
      assert.equal(typeof parse, 'function', name + ' needs native SEC parsing');
      calls = { count: 0 };
      addon.publicKeyParse = (...args) => {
        calls.count++;
        return parse(...args);
      };
    }
    const { BN, Point } = local('.').crypto;
    assert.equal(BN, originalBN);
    assert.deepEqual(Reflect.ownKeys(ec.curve), curveProperties);
    assert.deepEqual(Reflect.ownKeys(ec.g), generatorProperties);
    assert.equal(ec.curve._fixedNafMul, fixedNafMul);
    checkOverrides(Point);
    checkLargeBN(BN);
    if (calls) {
      const addon = local('./lib/native/bitcore_ecdsa.node');
      const parse = addon.publicKeyParse;
      const g = Point.getG();
      try {
        for (const fallback of [undefined, () => null]) {
          addon.publicKeyParse = fallback;
          assert(Point.fromX(false, g.getX()).eq(g));
        }
      } finally {
        addon.publicKeyParse = parse;
      }
    }
    return { name, Point, BN, ec, ellipticMul, ellipticAdd, bnMul, bnDiv, bnRedPow, calls };
  });
  // Exercise each package after all four have loaded into the same process.
  const results = libraries.map(checkLibrary);
  return createHash('sha256').update(JSON.stringify(results)).digest('hex');
}

if (parentPort) {
  parentPort.postMessage(runCorpus());
} else if (process.argv[2] === '--corpus') {
  process.stdout.write(runCorpus());
} else {
  const run = backend => new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { env: { ...process.env, BITCORE_ECDSA_BACKEND: backend } });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', code => {
      if (code !== 0) reject(new Error(`${backend} point corpus exited with status ${code}`));
    });
  });
  Promise.all([run('js'), run('native')]).then(([js, native]) => {
    assert.equal(native, js);
    console.log('Public BN and point operations matched across both backends for all four libraries.');
  });
}
