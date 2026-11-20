'use strict';

const BufferUtil = require('../util/buffer');
const Hash = require('./hash');

const sha512hmac = Hash.sha512hmac;

function encodePath(indexes, chainCode) {
  // JavaScript accepts some indexes that cannot be passed as a uint32.
  if (Hash.sha512hmac !== sha512hmac || indexes.length === 0 || indexes.length > 255 ||
      !isNativeBuffer(chainCode, 32) ||
      !indexes.every(index => Number.isInteger(index) && index >= 0 && index <= 0xffffffff)) {
    return;
  }

  const path = Buffer.alloc(indexes.length * 4);
  for (const [offset, index] of indexes.entries()) {
    path.writeUInt32BE(index, offset * 4);
  }
  return path;
}

function isNativeBuffer(value, length) {
  return BufferUtil.isBuffer(value) && value.length === length && value.buffer instanceof ArrayBuffer;
}

function parentFingerPrint(parent, indexes, parentPublicKey) {
  return indexes.length === 1 ? parent.fingerPrint : Hash.sha256ripemd160(parentPublicKey).subarray(0, 4);
}

function checkResult(result, length) {
  if (!Buffer.isBuffer(result) || result.length !== length) {
    throw new Error('Invalid result from native Bitcore key derivation');
  }
}

function checkPublicPrefix(prefix) {
  if (prefix !== 2 && prefix !== 3) throw new Error('Invalid compressed native public key');
}

module.exports = { encodePath, isNativeBuffer, parentFingerPrint, checkResult, checkPublicPrefix };
