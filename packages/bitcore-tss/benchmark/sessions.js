'use strict';

const assert = require('node:assert/strict');
const { DklsDkg, DklsDsg } = require('@bitgo/sdk-lib-mpc');
const bitcore = require('@bitpay-labs/bitcore-lib');
const { ECDSA: { KeyGen, Sign } } = require('..');
const { DklsComms } = require('../ecdsa/dklsComms');

async function rounds(parties) {
  let messages = [];
  for (const party of parties) messages.push(await party.initJoin());
  for (let i = 1; i <= 4; i++) {
    messages = parties.map((party, id) => party.nextRound(messages
      .filter(m => m.partyId !== id)
      .map(m => ({ ...m, p2pMessages: m.p2pMessages.filter(p => p.to === id) }))));
  }
}

// These methods are synchronous. SDK initialization and serialization are included only in totalMs.
async function measure(run, sdk) {
  const elapsed = { commsMs: 0, sdkRoundMs: 0 };
  const restore = [];
  function time(object, method, bucket) {
    const original = object[method];
    object[method] = function(...args) {
      const start = performance.now();
      try { return original.apply(this, args); }
      finally { elapsed[bucket] += performance.now() - start; }
    };
    restore.push(() => { object[method] = original; });
  }
  time(DklsComms, 'encryptAndAuthOutgoingMessages', 'commsMs');
  time(DklsComms, 'decryptAndVerifyIncomingMessages', 'commsMs');
  time(sdk.prototype, 'handleIncomingMessages', 'sdkRoundMs');
  try {
    const start = performance.now();
    const result = await run();
    return { result, timing: { totalMs: performance.now() - start, ...elapsed } };
  } finally {
    for (const fn of restore) fn();
  }
}

async function sample() {
  const auth = Array.from({ length: 3 }, () => new bitcore.PrivateKey());
  const messageHash = bitcore.crypto.Hash.sha256(Buffer.from('Bitcore session benchmark'));
  const { result: shares, timing: keygen } = await measure(async () => {
    const parties = auth.map((authKey, partyId) => new KeyGen({ n: 3, m: 2, authKey, partyId }));
    await rounds(parties);
    return parties.map(p => p.getKeyChain());
  }, DklsDkg.Dkg);
  const common = shares[0].commonKeyChain.toString('hex');
  assert(shares.every(s => s.commonKeyChain.toString('hex') === common));
  const { result: signatures, timing: sign } = await measure(async () => {
    const parties = auth.slice(0, 2).map((authKey, partyId) =>
      new Sign({ n: 3, m: 2, authKey, partyId, keychain: shares[partyId], messageHash }));
    await rounds(parties);
    return parties.map(p => p.getSignature());
  }, DklsDsg.Dsg);
  assert.deepEqual(signatures[0], signatures[1]);
  const { r, s } = signatures[0];
  const signature = bitcore.crypto.Signature.fromCompact(Buffer.from('1b' + r.slice(2) + s.slice(2), 'hex'));
  assert(bitcore.crypto.ECDSA.verify(messageHash, signature, Buffer.from(common.slice(0, 66), 'hex')));
  return { keygen, sign };
}

async function main() {
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const { native } = require('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
    const sign = native.sign;
    let signedNatively = false;
    native.sign = (...args) => {
      const result = sign(...args);
      if (result) signedNatively = true;
      return result;
    };
    try {
      await sample();
      assert(signedNatively, 'TSS message authentication skipped native ECDSA');
    } finally {
      native.sign = sign;
    }
  } else {
    await sample();
  }
  const samples = [];
  for (let i = 0; i < 5; i++) samples.push(await sample());
  const median = {};
  for (const phase of ['keygen', 'sign']) {
    median[phase] = {};
    for (const field of Object.keys(samples[0][phase])) {
      median[phase][field] = samples.map(r => r[phase][field]).sort((a, b) => a - b)[2];
    }
  }
  console.log(JSON.stringify({ backend: process.env.BITCORE_ECDSA_BACKEND || 'auto', median, samples }, null, 2));
}

main().catch(err => { console.error(err); process.exitCode = 1; });
