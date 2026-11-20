'use strict';

var _ = require('lodash');
var buffer = require('buffer');

const CHARACTERS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
var ALPHABET = CHARACTERS.split('');
const DIGITS = new Int8Array(128).fill(-1);
for (let i = 0; i < CHARACTERS.length; i++) DIGITS[CHARACTERS.charCodeAt(i)] = i;

// Process three bytes or four Base58 digits at a time. Products of the two
// radices (2^24 and 58^4) fit below 2^48, so carries are exact JS integers.
const BYTE_RADIX = 0x1000000;
const BASE58_RADIX = 58 ** 4;

var Base58 = function Base58(obj) {
  /* jshint maxcomplexity: 8 */
  if (!(this instanceof Base58)) {
    return new Base58(obj);
  }
  if (Buffer.isBuffer(obj)) {
    var buf = obj;
    this.fromBuffer(buf);
  } else if (typeof obj === 'string') {
    var str = obj;
    this.fromString(str);
  } else if (obj) {
    this.set(obj);
  }
};

Base58.validCharacters = function validCharacters(chars) {
  if (buffer.Buffer.isBuffer(chars)) {
    chars = chars.toString();
  }
  return _.every(_.map(chars, function(char) { return _.includes(ALPHABET, char); }));
};

Base58.prototype.set = function(obj) {
  this.buf = obj.buf || this.buf || undefined;
  return this;
};

Base58.encode = function(buf) {
  if (!buffer.Buffer.isBuffer(buf)) {
    throw new Error('Input should be a buffer');
  }
  let offset = 0;
  while (offset < buf.length && buf[offset] === 0) offset++;
  let result = '1'.repeat(offset);
  const limbs = [];
  while (offset < buf.length) {
    const end = Math.min(offset + 3, buf.length);
    const factor = 1 << ((end - offset) * 8);
    let carry = 0;
    while (offset < end) carry = (carry << 8) | buf[offset++];
    for (let i = 0; i < limbs.length; i++) {
      carry += limbs[i] * factor;
      limbs[i] = carry % BASE58_RADIX;
      carry = Math.floor(carry / BASE58_RADIX);
    }
    while (carry) {
      limbs.push(carry % BASE58_RADIX);
      carry = Math.floor(carry / BASE58_RADIX);
    }
  }
  for (let i = limbs.length - 1; i >= 0; i--) {
    let limb = limbs[i];
    let digits = '';
    do {
      digits = CHARACTERS[limb % 58] + digits;
      limb = Math.floor(limb / 58);
    } while (limb || (i !== limbs.length - 1 && digits.length < 4));
    result += digits;
  }
  return result;
};

Base58.decode = function(str) {
  if (typeof str !== 'string') {
    throw new Error('Input should be a string');
  }
  let offset = 0;
  while (offset < str.length && str[offset] === '1') offset++;
  const zeroes = offset;
  if (offset === str.length) return Buffer.alloc(zeroes);

  const limbs = [];
  while (offset < str.length) {
    const end = Math.min(offset + 4, str.length);
    const factor = 58 ** (end - offset);
    let carry = 0;
    while (offset < end) {
      const digit = DIGITS[str.charCodeAt(offset++)];
      if (!(digit >= 0)) throw new Error('Non-base58 character');
      carry = carry * 58 + digit;
    }
    for (let i = 0; i < limbs.length; i++) {
      carry += limbs[i] * factor;
      limbs[i] = carry & (BYTE_RADIX - 1);
      carry = Math.floor(carry / BYTE_RADIX);
    }
    if (carry) limbs.push(carry);
  }
  const head = limbs[limbs.length - 1];
  const length = zeroes + (limbs.length - 1) * 3 + (head >>> 16 ? 3 : head >>> 8 ? 2 : 1);
  const result = Buffer.alloc(length);
  offset = length;
  for (let limb of limbs) {
    for (let byte = 0; byte < 3 && offset > zeroes; byte++) {
      result[--offset] = limb;
      limb >>>= 8;
    }
  }
  return result;
};

Base58.prototype.fromBuffer = function(buf) {
  this.buf = buf;
  return this;
};

Base58.prototype.fromString = function(str) {
  var buf = Base58.decode(str);
  this.buf = buf;
  return this;
};

Base58.prototype.toBuffer = function() {
  return this.buf;
};

Base58.prototype.toString = function() {
  return Base58.encode(this.buf);
};

module.exports = Base58;
