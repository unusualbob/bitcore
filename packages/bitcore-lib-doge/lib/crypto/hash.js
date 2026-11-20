'use strict';

var nodeCrypto = require('crypto');
var Scrypt = require('scryptsy');
var BufferUtil = require('../util/buffer');
var $ = require('../util/preconditions');
const { native } = require('./ecdsa-native');

var Hash = module.exports;
const hasFipsCheck = typeof nodeCrypto.getFips === 'function';
const hasOneShotHash = hasFipsCheck && typeof nodeCrypto.hash === 'function';

Hash.sha1 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return nodeCrypto.createHash('sha1').update(buf).digest();
};

Hash.sha1.blocksize = 512;

Hash.sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  if (hasOneShotHash && !nodeCrypto.getFips()) {
    return nodeCrypto.hash('sha256', buf, 'buffer');
  }
  return nodeCrypto.createHash('sha256').update(buf).digest();
};

Hash.sha256.blocksize = 512;

Hash.sha256sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.sha256(Hash.sha256(buf));
};

Hash.ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return nodeCrypto.createHash('ripemd160').update(buf).digest();
};

Hash.sha256ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.ripemd160(Hash.sha256(buf));
};

Hash.sha512 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return nodeCrypto.createHash('sha512').update(buf).digest();
};

Hash.sha512.blocksize = 1024;

const sha256 = Hash.sha256;
const sha512 = Hash.sha512;
// Browser crypto shims use the existing HMAC implementation.
const hasNativeHmac = hasFipsCheck && typeof nodeCrypto.createHmac === 'function';

Hash.hmac = function(hashf, data, key) {
  // http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  // http://tools.ietf.org/html/rfc4868#section-2
  $.checkArgument(BufferUtil.isBuffer(data));
  $.checkArgument(BufferUtil.isBuffer(key));
  $.checkArgument(hashf.blocksize);

  var blocksize = hashf.blocksize / 8;

  // Keep the generic path for custom hash functions and historical typed-array keys.
  if (hasNativeHmac && Buffer.isBuffer(data) && Buffer.isBuffer(key) && !nodeCrypto.getFips()) {
    if (hashf === sha256 && blocksize === 64) {
      return nodeCrypto.createHmac('sha256', key).update(data).digest();
    }
    if (hashf === sha512 && blocksize === 128) {
      return nodeCrypto.createHmac('sha512', key).update(data).digest();
    }
  }

  if (key.length > blocksize) {
    key = hashf(key);
  } else if (key < blocksize) {
    var fill = Buffer.alloc(blocksize);
    fill.fill(0);
    key.copy(fill);
    key = fill;
  }

  var o_key = Buffer.alloc(blocksize);
  o_key.fill(0x5c);

  var i_key = Buffer.alloc(blocksize);
  i_key.fill(0x36);

  var o_key_pad = Buffer.alloc(blocksize);
  var i_key_pad = Buffer.alloc(blocksize);
  for (var i = 0; i < blocksize; i++) {
    o_key_pad[i] = o_key[i] ^ key[i];
    i_key_pad[i] = i_key[i] ^ key[i];
  }

  return hashf(Buffer.concat([o_key_pad, hashf(Buffer.concat([i_key_pad, data]))]));
};

Hash.sha256hmac = function(data, key) {
  return Hash.hmac(Hash.sha256, data, key);
};

Hash.sha512hmac = function(data, key) {
  return Hash.hmac(Hash.sha512, data, key);
};

Hash.scrypt = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  if (!nodeCrypto.getFips?.()) {
    if (typeof native?.scryptProofOfWork === 'function' && buf.length === 80 && buf.buffer instanceof ArrayBuffer) {
      return native.scryptProofOfWork(buf).reverse();
    }
    if (typeof nodeCrypto.scryptSync === 'function') {
      let hash;
      try {
        hash = nodeCrypto.scryptSync(buf, buf, 32, { N: 1024, r: 1, p: 1 });
      } catch (error) {
        // Node can report an unavailable provider through its parameter check.
        const unsupported = error?.code === 'ERR_CRYPTO_SCRYPT_NOT_SUPPORTED' ||
          error?.code === 'ERR_OSSL_EVP_UNSUPPORTED' ||
          (error?.code === 'ERR_CRYPTO_INVALID_SCRYPT_PARAMS' &&
            typeof error.message === 'string' && error.message.endsWith('digital envelope routines::unsupported'));
        if (!unsupported) throw error;
        hash = Scrypt(buf, buf, 1024, 1, 1, 32);
      }
      return hash.reverse();
    }
  }
  return BufferUtil.reverse(Scrypt(buf, buf, 1024, 1, 1, 32));
};
