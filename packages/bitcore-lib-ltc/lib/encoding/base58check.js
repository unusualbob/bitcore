'use strict';

const { getFips } = require('crypto');
var _ = require('lodash');
const { native } = require('../crypto/ecdsa-native');
const Hash = require('../crypto/hash');
const Base58 = require('./base58');

const nativeEncode = native?.base58CheckEncode;
const nativeDecode = native?.base58DecodeChecked;
const { sha256, sha256sha256 } = Hash;
const encodeBase58 = Base58.encode;
const decodeBase58 = Base58.decode;

function checksum(data) {
  return sha256sha256(data).slice(0, 4);
}

var Base58Check = function Base58Check(obj) {
  if (!(this instanceof Base58Check))
    return new Base58Check(obj);
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

Base58Check.prototype.set = function(obj) {
  this.buf = obj.buf || this.buf || undefined;
  return this;
};

Base58Check.validChecksum = function validChecksum(data, checksum) {
  if (_.isString(data)) {
    data = new Buffer.from(Base58.decode(data));
  }
  if (_.isString(checksum)) {
    checksum = new Buffer.from(Base58.decode(checksum));
  }
  if (!checksum) {
    checksum = data.slice(-4);
    data = data.slice(0, -4);
  }
  return Base58Check.checksum(data).toString('hex') === checksum.toString('hex');
};

Base58Check.decode = function(s) {
  if (typeof s !== 'string')
    throw new Error('Input must be a string');

  if (nativeDecode && s.length >= 24 && s.length <= 177 &&
      Base58.decode === decodeBase58 && Hash.sha256 === sha256 && !getFips?.()) {
    const decoded = nativeDecode(s);
    if (decoded !== null) return decoded.slice(0, -4);
  }

  var buf = Base58.decode(s);

  if (buf.length < 4)
    throw new Error('Input string too short');

  var data = buf.slice(0, -4);
  var csum = buf.slice(-4);

  var hash4 = checksum(data);

  if (!csum.equals(hash4))
    throw new Error('Checksum mismatch');

  return data;
};

Base58Check.checksum = checksum;

Base58Check.encode = function(buf) {
  if (!Buffer.isBuffer(buf))
    throw new Error('Input must be a buffer');
  if (nativeEncode && buf.length >= 20 && buf.length <= 124 &&
      Base58.encode === encodeBase58 && Base58Check.checksum === checksum &&
      Hash.sha256 === sha256 && buf.copy === Buffer.prototype.copy && !getFips?.()) {
    const encoded = nativeEncode(buf);
    if (encoded !== null) return encoded;
  }
  var checkedBuf = Buffer.alloc(buf.length + 4);
  var hash = Base58Check.checksum(buf);
  buf.copy(checkedBuf);
  hash.copy(checkedBuf, buf.length);
  return Base58.encode(checkedBuf);
};

Base58Check.prototype.fromBuffer = function(buf) {
  this.buf = buf;
  return this;
};

Base58Check.prototype.fromString = function(str) {
  var buf = Base58Check.decode(str);
  this.buf = buf;
  return this;
};

Base58Check.prototype.toBuffer = function() {
  return this.buf;
};

Base58Check.prototype.toString = function() {
  return Base58Check.encode(this.buf);
};

module.exports = Base58Check;
