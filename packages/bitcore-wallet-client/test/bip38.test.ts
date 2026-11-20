import assert from 'assert/strict';
import crypto from 'crypto';
import sinon from 'sinon';
import { API } from '../src/lib/api';

describe('BIP38 private key import', function() {
  this.timeout(15_000);

  // The direct-encryption vector also appears in the pinned bip38 README.
  const direct = {
    encrypted: '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg',
    passphrase: 'TestingOneTwoThree',
    wif: '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
  };
  // EC-multiply fixture from the original API import test.
  const ecMultiply = {
    encrypted: '6PfRh9ZnWtiHrGoPPSzXe6iafTXc6FSXDhSBuDvvDmGd1kpX2Gvy1CfTcA',
    passphrase: 'passphrase',
    wif: '5KjBgBiadWGhjWmLN1v4kcEZqWSZFqzgv7cSUuZNJg4tD82c4xp'
  };

  const client = new API();
  const sandbox = sinon.createSandbox();
  afterEach(() => sandbox.restore());

  for (const [name, fixture] of Object.entries({ direct, 'EC-multiply': ecMultiply })) {
    it(`imports the ${name} format`, function() {
      const scrypt = sandbox.spy(crypto, 'scryptSync');
      assert.equal(client.decryptBIP38PrivateKey(fixture.encrypted, fixture.passphrase, undefined), fixture.wif);
      if (!crypto.getFips()) {
        assert.equal(scrypt.callCount, name === 'direct' ? 1 : 2);
      }
    });
  }

  it('reports legacy scrypt progress when a progress callback is supplied', function() {
    const scrypt = sandbox.spy(crypto, 'scryptSync');
    const progress = sandbox.spy();
    assert.equal(client.decryptBIP38PrivateKey(direct.encrypted, direct.passphrase, progress), direct.wif);
    assert.equal(scrypt.callCount, 0);
    assert(progress.called);
    const [first] = progress.firstCall.args;
    const [last] = progress.lastCall.args;
    assert(first.current > 0 && first.current <= first.total);
    assert.equal(first.percent, 100 * first.current / first.total);
    assert(last.current > first.current && last.current <= last.total);
    assert.equal(last.total, first.total);
  });

  it('retries with the legacy provider if OpenSSL scrypt fails', function() {
    const scrypt = sandbox.stub(crypto, 'scryptSync').throws(new Error('scrypt is unavailable'));
    sandbox.stub(crypto, 'getFips').returns(0);
    assert.equal(client.decryptBIP38PrivateKey(ecMultiply.encrypted, ecMultiply.passphrase, undefined), ecMultiply.wif);
    assert.equal(scrypt.callCount, 1);
  });
});
