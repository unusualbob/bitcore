'use strict';

const BufferWriter = require('../encoding/bufferwriter');

const scopes = new WeakMap();

function cachedHash(transaction, field, compute) {
  const scope = scopes.get(transaction);
  if (!scope) return compute();
  if (scope[field] == null) scope[field] = compute();
  return scope[field];
}

function legacyTemplate(transaction, clone, index) {
  const scope = scopes.get(transaction);
  if (!scope || index >= transaction.inputs.length) return;
  if (!scope.legacyTemplate) {
    const snapshot = clone(transaction);
    const writer = new BufferWriter().writeInt32LE(snapshot.version).writeVarintNum(snapshot.inputs.length);
    const scriptOffsets = [];
    for (const input of snapshot.inputs) {
      writer.writeReverse(input.prevTxId).writeUInt32LE(input.outputIndex);
      scriptOffsets.push(writer.bufLen);
      writer.writeUInt8(0).writeUInt32LE(input.sequenceNumber);
    }
    writer.writeVarintNum(snapshot.outputs.length);
    for (const output of snapshot.outputs) output.toBufferWriter(writer);
    writer.writeUInt32LE(snapshot.nLockTime);
    scope.legacyTemplate = { bytes: writer.toBuffer(), scriptOffsets };
  }
  return scope.legacyTemplate;
}

function legacyPreimage(template, index, script, sighashType) {
  const { bytes, scriptOffsets } = template;
  const offset = scriptOffsets[index];
  return new BufferWriter()
    .write(bytes.subarray(0, offset))
    .writeVarintNum(script.length)
    .write(script)
    .write(bytes.subarray(offset + 1))
    .writeInt32LE(sighashType)
    .toBuffer();
}

function createScope(Input, Output, Hash, canCopy) {
  const names = [
    'getSignatures', 'addSignature', 'isValidSignature', 'getSatoshisBuffer',
    'getScriptCode', 'getRedeemScript', 'isFullySigned', '_updateScript',
    'setScript', 'setWitnesses', 'hasWitnesses', 'getWitnesses', 'isNull', 'toBufferWriter'
  ];
  const types = [Input, ...Object.values(Input).filter(type => typeof type === 'function' && type.prototype)];
  const methods = new Map(types.map(({ prototype }) => [prototype, names.map(name => prototype[name])]));
  const writeOutput = Output.prototype.toBufferWriter;
  const { sha256, sha256sha256 } = Hash;
  const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const isData = (object, key) => {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    return descriptor && hasOwn(descriptor, 'value');
  };
  const isOutput = output => output && Object.getPrototypeOf(output) === Output.prototype &&
    output.toBufferWriter === writeOutput && !hasOwn(output, 'script');
  const isInput = input => {
    const original = input && methods.get(Object.getPrototypeOf(input));
    return original && names.every((name, index) => !hasOwn(input, name) && input[name] === original[index]) &&
      ['output', 'prevTxId', 'outputIndex', 'sequenceNumber'].every(key => isData(input, key)) &&
      Buffer.isBuffer(input.prevTxId) && input.prevTxId.length === 32 &&
      input.prevTxId.buffer instanceof ArrayBuffer &&
      typeof input.outputIndex === 'number' && typeof input.sequenceNumber === 'number' &&
      isOutput(input.output);
  };

  return function withSighashCache(transaction, run) {
    // Scope hashes to one synchronous operation on ordinary inputs and outputs.
    // Witness and fork-ID hashes never include the script signatures being set.
    if (scopes.has(transaction) ||
        !['inputs', 'outputs', 'version', 'nLockTime'].every(key => isData(transaction, key)) ||
        typeof transaction.version !== 'number' || typeof transaction.nLockTime !== 'number' ||
        !Array.isArray(transaction.inputs) || !Array.isArray(transaction.outputs) ||
        transaction.inputs.every !== Array.prototype.every || transaction.outputs.every !== Array.prototype.every ||
        transaction.inputs.length < 2 || Hash.sha256 !== sha256 || Hash.sha256sha256 !== sha256sha256 ||
        !canCopy(transaction) || !transaction.inputs.every(isInput) || !transaction.outputs.every(isOutput)) {
      return run();
    }
    scopes.set(transaction, Object.create(null));
    try {
      return run();
    } finally {
      scopes.delete(transaction);
    }
  };
}

module.exports = { cachedHash, createScope, legacyPreimage, legacyTemplate };
