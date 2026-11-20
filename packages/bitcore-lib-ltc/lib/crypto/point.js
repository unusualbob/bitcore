'use strict';

var BN = require('./bn');
var BufferUtil = require('../util/buffer');

var EC = require('elliptic').ec;
const { native } = require('./ecdsa-native');

const { curve } = new EC('secp256k1');
const ecPoint = curve.point.bind(curve);
const ecPointFromX = curve.pointFromX.bind(curve);
const CoordinateBN = curve.p.constructor;
const fieldHex = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';
const fieldSize = new CoordinateBN(fieldHex, 16);
const order = new CoordinateBN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
const red = curve.red;
const seven = new CoordinateBN(7);

// The public Point and BN objects expose the underlying elliptic objects.
// Keep the original path when a caller has customized the methods it uses.
function methodValue(object, name) {
  for (let owner = object; owner; owner = Object.getPrototypeOf(owner)) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor) return descriptor.value;
  }
}

function standardMethods(object, names) {
  const methods = names.map(name => [name, methodValue(object, name)]);
  return () => methods.every(([name, method]) => typeof method === 'function' && methodValue(object, name) === method);
}

const coordinateMethods = [
  'cmp', 'cmpn', 'clone', 'mul', 'toArray', 'toArrayLike', 'fromRed', 'toRed', 'isOdd',
  'redSqrt', 'redSqr', 'redMul', 'redIAdd', 'redSub', 'redISub', 'redNeg'
];
const standardCoordinates = standardMethods(CoordinateBN.prototype, coordinateMethods);
const standardBN = standardMethods(BN.prototype, coordinateMethods);
const standardCurve = standardMethods(curve, [
  'point', 'validate', '_endoWnafMulAdd', '_endoSplit', '_wnafMulAdd', 'jpoint'
]);
const standardReduction = standardMethods(red, [
  'convertTo', 'convertFrom', 'sqrt', 'pow', 'sqr', 'mul', 'iadd', 'sub', 'isub', 'neg', 'imod'
]);

function hasStandardCurve() {
  return standardCoordinates() && standardBN() && standardCurve() && standardReduction() &&
    curve.red === red && red.m.cmp(fieldSize) === 0 && curve.p.cmp(fieldSize) === 0 &&
    curve.a.red === red && curve.b.red === red && curve.a.cmpn(0) === 0 &&
    curve.b.cmp(seven) === 0 && curve.zero.cmpn(0) === 0;
}

function isCoordinate(value, context) {
  if (!value || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  // An ordinary bn.js instance owns only negative, words, length and red.
  if ((prototype !== CoordinateBN.prototype && prototype !== BN.prototype) ||
      Object.getOwnPropertyNames(value).length !== 4 || value.red !== context || value.negative !== 0 ||
      !Number.isInteger(value.length) || value.length < 1 || value.length > fieldSize.length ||
      !Array.isArray(value.words) || (value.length > 1 && value.words[value.length - 1] === 0)) {
    return false;
  }
  for (let i = 0; i < value.length; i++) {
    if ((value.words[i] & 0x3ffffff) !== value.words[i]) return false;
  }
  return value.cmp(fieldSize) < 0;
}

function pointFromX(odd, x) {
  if (typeof native?.publicKeyParse === 'function' && typeof odd === 'boolean' && hasStandardCurve()) {
    // Preserve bn.js's accepted input forms and coordinate class. A red input
    // can also alias the returned point's x, so it stays on the original path.
    if (typeof x === 'string' && /^[0-9a-f]{1,64}$/i.test(x)) x = new CoordinateBN(x, 16);
    if (isCoordinate(x, null)) {
      const sec = x.toArrayLike(Buffer, 'be', 33);
      sec[0] = odd ? 3 : 2;
      const xy = native.publicKeyParse(sec);
      if (xy) return ecPoint(x, new CoordinateBN(xy.subarray(33)));
    }
  }
  return ecPointFromX(x, odd);
}

/**
 *
 * Instantiate a valid secp256k1 Point from the X and Y coordinates.
 *
 * @param {BN|String} x - The X coordinate
 * @param {BN|String} y - The Y coordinate
 * @link https://github.com/indutny/elliptic
 * @augments elliptic.curve.point
 * @throws {Error} A validation error if exists
 * @returns {Point} An instance of Point
 * @constructor
 */
var Point = function Point(x, y, isRed) {
  try {
    var point = ecPoint(x, y, isRed);
  } catch (e) {
    throw new Error('Invalid Point');
  }
  point.validate();
  return point;
};

Point.prototype = Object.getPrototypeOf(curve.point());

/**
 *
 * Instantiate a valid secp256k1 Point from only the X coordinate
 *
 * @param {boolean} odd - If the Y coordinate is odd
 * @param {BN|String} x - The X coordinate
 * @throws {Error} A validation error if exists
 * @returns {Point} An instance of Point
 */
Point.fromX = function fromX(odd, x){
  try {
    var point = pointFromX(odd, x);
  } catch (e) {
    throw new Error('Invalid X');
  }
  point.validate();
  return point;
};

/**
 *
 * Will return a secp256k1 ECDSA base point.
 *
 * @link https://en.bitcoin.it/wiki/Secp256k1
 * @returns {Point} An instance of the base point.
 */
Point.getG = function getG() {
  return curve.g;
};

/**
 *
 * Will return the max of range of valid private keys as governed by the secp256k1 ECDSA standard.
 *
 * @link https://en.bitcoin.it/wiki/Private_key#Range_of_valid_ECDSA_private_keys
 * @returns {BN} A BN instance of the number of points on the curve
 */
Point.getN = function getN() {
  return new BN(curve.n.toArray());
};
const getN = Point.getN;

if (!Point.prototype._getX)
Point.prototype._getX = Point.prototype.getX;

/**
 *
 * Will return the X coordinate of the Point
 *
 * @returns {BN} A BN instance of the X coordinate
 */
Point.prototype.getX = function getX() {
  return new BN(this._getX().toArray());
};

if (!Point.prototype._getY)
Point.prototype._getY = Point.prototype.getY;

/**
 *
 * Will return the Y coordinate of the Point
 *
 * @returns {BN} A BN instance of the Y coordinate
 */
Point.prototype.getY = function getY() {
  return new BN(this._getY().toArray());
};

const standardPoint = standardMethods(Point.prototype, [
  'getX', 'getY', '_getX', '_getY', 'isInfinity', 'mul', '_hasDoubles', '_getBeta',
  '_getNAFPoints', 'dbl', 'neg', 'add', 'eq', 'toJ'
]);

function isOnStandardCurve(point) {
  try {
    // secp256k1 has cofactor one, so a finite point on it already belongs to
    // the order-N group. Let the original validation handle error reporting.
    // An ordinary elliptic point owns curve, type, precomputed, x, y and inf.
    return Object.getPrototypeOf(point) === Point.prototype && point.curve === curve &&
      point.precomputed === null && Object.getOwnPropertyNames(point).length === 6 &&
      methodValue(Point, 'getN') === getN && standardPoint() && hasStandardCurve() && curve.n.cmp(order) === 0 &&
      methodValue(curve.n, 'toArray') === CoordinateBN.prototype.toArray &&
      isCoordinate(point.x, red) && isCoordinate(point.y, red) && curve.validate(point);
  } catch {
    return false;
  }
}

/**
 *
 * Will determine if the point is valid
 *
 * @link https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf
 * @param {Point} An instance of Point
 * @throws {Error} A validation error if exists
 * @returns {Point} An instance of the same Point
 */
Point.prototype.validate = function validate() {

  if (this.isInfinity()){
    throw new Error('Point cannot be equal to Infinity');
  }

  if (isOnStandardCurve(this)) return this;

  var p2;
  try {
    p2 = ecPointFromX(this.getX(), this.getY().isOdd());
  } catch (e) {
    throw new Error('Point does not lie on the curve');
  }

  if (p2.y.cmp(this.y) !== 0) {
    throw new Error('Invalid y value for curve.');
  }


  //todo: needs test case
  if (!(this.mul(Point.getN()).isInfinity())) {
    throw new Error('Point times N must be infinity');
  }

  return this;

};

Point.pointToCompressed = function pointToCompressed(point) {
  var xbuf = point.getX().toBuffer({size: 32});
  var ybuf = point.getY().toBuffer({size: 32});

  var prefix;
  var odd = ybuf[ybuf.length - 1] % 2;
  if (odd) {
    prefix = Buffer.from([0x03]);
  } else {
    prefix = Buffer.from([0x02]);
  }
  return BufferUtil.concat([prefix, xbuf]);
};

module.exports = Point;
