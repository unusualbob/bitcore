'use strict';

const nodeCrypto = require('crypto');
const { types } = require('util');
const BufferUtil = require('../util/buffer');
const { native } = require('./ecdsa-native');

const { createHash, hash, getHashes } = nodeCrypto;
const isBuffer = BufferUtil.isBuffer;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const arrayBuffer = Object.getOwnPropertyDescriptor(typedArray, 'buffer').get;
const byteLength = Object.getOwnPropertyDescriptor(typedArray, 'byteLength').get;

// Keep larger serialized transactions on OpenSSL.
const MAX_NATIVE_SHA256D_BYTES = 512;

function canHashNatively(buf, limit, algorithm) {
  if (!Buffer.isBuffer(buf) || !types?.isUint8Array(buf)) return false;
  const length = byteLength.call(buf);
  if (length === 0 || length > limit || BufferUtil.isBuffer !== isBuffer ||
      nodeCrypto.createHash !== createHash || nodeCrypto.hash !== hash ||
      typeof nodeCrypto.getFips !== 'function' || nodeCrypto.getFips() ||
      !types.isArrayBuffer(arrayBuffer.call(buf))) {
    return false;
  }
  const algorithms = getHashes?.();
  return algorithms?.includes('sha256') && (algorithm === 'sha256' || algorithms.includes(algorithm));
}

function createHash256(Hash) {
  const { sha256, sha256sha256 } = Hash;
  return function hash256(buf) {
    if (typeof native?.hash256 === 'function' && Hash.sha256 === sha256 && Hash.sha256sha256 === sha256sha256 &&
        canHashNatively(buf, MAX_NATIVE_SHA256D_BYTES, 'sha256')) {
      return native.hash256(buf);
    }
    return Hash.sha256sha256(buf);
  };
}

module.exports = { canHashNatively, createHash256 };
