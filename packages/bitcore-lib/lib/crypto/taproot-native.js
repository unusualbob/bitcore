'use strict';

const { native } = require('./ecdsa-native');
const Hash = require('./hash');
const TaggedHash = require('./taggedhash');

const sha256 = Hash.sha256;
const finalize = TaggedHash.prototype.finalize;

function usesDefaultTaggedHash() {
  return Hash.sha256 === sha256 && TaggedHash.prototype.finalize === finalize;
}

function supportedBuffer(value, length) {
  return Buffer.isBuffer(value) && value.length === length && value.buffer instanceof ArrayBuffer;
}

function checkBuffer(result, length) {
  if (!Buffer.isBuffer(result) || result.length !== length) {
    throw new Error('Invalid result from native Bitcore Taproot operations');
  }
  return result;
}

module.exports = { native, usesDefaultTaggedHash, supportedBuffer, checkBuffer };
