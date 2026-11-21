'use strict';

const nodeCrypto = require('crypto');
const { hasStandardBNEncoding } = require('../crypto/bip32-native');
const BN = require('../crypto/bn');
const Hash = require('../crypto/hash');
const Schnorr = require('../crypto/schnorr');
const Signature = require('../crypto/signature');
const { native, supportedBuffer, usesDefaultTaggedHash } = require('../crypto/taproot-native');
const Opcode = require('../opcode');
const PrivateKey = require('../privatekey');
const Script = require('../script');
const TaprootInput = require('./input/taproot');
const SighashSchnorr = require('./sighashschnorr');

const randomBytes = nodeCrypto.randomBytes;
const createTapTweak = PrivateKey.prototype.createTapTweak;
const toPublicKey = PrivateKey.prototype.toPublicKey;
const scriptToBuffer = Script.prototype.toBuffer;
const isTaproot = Script.prototype.isTaproot;
const schnorrSign = Schnorr.sign;
const schnorrVerify = Schnorr.verify;
const sighashSign = SighashSchnorr.sign;
const sighashVerify = SighashSchnorr.verify;
const sighash = SighashSchnorr.sighash;
const { schnorrSign: nativeSign, schnorrVerify: nativeVerify, taprootPrivateTweak: nativeTweak } = native || {};

function getInputPositions(transaction) {
  const positions = new Map();
  for (const [index, input] of transaction.inputs.entries()) {
    if (Object.getPrototypeOf(input) !== TaprootInput.prototype) return;
    const script = input.output.script;
    if (!script || Object.getPrototypeOf(script) !== Script.prototype ||
        script.toBuffer !== scriptToBuffer || script.isTaproot !== isTaproot) return;

    const bytes = script.toBuffer();
    if (bytes.length !== 34 || bytes[0] !== Opcode.OP_1 || bytes[1] !== 32) return;
    const program = script.chunks[1]?.buf;
    if (!supportedBuffer(program, 32) || !program.equals(bytes.subarray(2))) return;
    const compressed = Buffer.concat([Buffer.from([2]), program]);
    if (native.publicKeyParse(compressed) == null) return;
    const x = program.toString('hex');
    const indexes = positions.get(x);
    if (indexes) indexes.push(index);
    else positions.set(x, [index]);
  }
  return positions;
}

function findMatchingInputs(transaction, keys) {
  if (typeof native?.publicKeyCreate !== 'function' || typeof native?.publicKeyParse !== 'function' ||
      typeof nativeTweak !== 'function' || typeof nativeSign !== 'function' || typeof nativeVerify !== 'function' ||
      PrivateKey.prototype.toPublicKey !== toPublicKey || nodeCrypto.randomBytes !== randomBytes ||
      native.taprootPrivateTweak !== nativeTweak || native.schnorrSign !== nativeSign || native.schnorrVerify !== nativeVerify ||
      !usesDefaultTaggedHash() || Schnorr.sign !== schnorrSign || Schnorr.verify !== schnorrVerify ||
      SighashSchnorr.sign !== sighashSign || SighashSchnorr.verify !== sighashVerify ||
      SighashSchnorr.sighash !== sighash) return;

  try {
    const positions = getInputPositions(transaction);
    if (!positions) return;
    const matches = [];
    for (const key of keys) {
      if (!key || Object.getPrototypeOf(key) !== PrivateKey.prototype || key.createTapTweak !== createTapTweak ||
          !(key.bn instanceof BN) || !hasStandardBNEncoding(key.bn) || key.bn.isNeg() || key.bn.byteLength() > 32) return;
      const { tweakedPrivKey } = key.createTapTweak();
      let pubKey;
      try {
        pubKey = native.publicKeyCreate(tweakedPrivKey, true);
      } finally {
        tweakedPrivKey.fill(0);
      }
      if (!Buffer.isBuffer(pubKey) || pubKey.length !== 33) return;
      matches.push(positions.get(pubKey.subarray(1).toString('hex')) || []);
    }
    // Check the common transaction fields even if there are no matching inputs.
    if (!sighash(transaction, Signature.SIGHASH_DEFAULT, 0, Signature.Version.TAPROOT, null)) return;
    return matches;
  } catch {
    // Preserve the ordinary signer's validation and error ordering.
  }
}

function getWalletTaprootSignatures(transaction, keys, signingMethod) {
  const matches = findMatchingInputs(transaction, keys);
  if (!matches) return;
  return keys.map((key, keyIndex) => {
    const hash = Hash.sha256ripemd160(key.publicKey.toBuffer());
    return matches[keyIndex].flatMap(index =>
      transaction.inputs[index].getSignatures(transaction, key, index, undefined, hash, signingMethod)
    );
  });
}

module.exports = { getWalletTaprootSignatures };
