import assert from 'assert/strict';
import sinon from 'sinon';
import sjcl from 'sjcl';
import { PushNotificationsService } from '../src/lib/pushnotificationsservice';

describe('Push notification identifiers', function() {
  const legacyHash = (id: string) => sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(id));

  it('preserves the hashes sent for wallet-scoped and subscription-scoped notifications', async function() {
    const service = new PushNotificationsService();
    const subscription = { walletId: 'subscribed-wallet', copayerId: 'f'.repeat(64), token: 'example' };
    sinon.stub(service, '_checkShouldSendNotif').callsArgWith(1, null, true);
    sinon.stub(service, '_getRecipientsList').callsArgWith(2, null, []);
    sinon.stub(service, '_readAndApplyTemplates').callsArgWith(3, null, []);
    sinon.stub(service, '_getSubscriptions').callsArgWith(4, null, [subscription]);
    const send = sinon.stub(service, '_makeRequest').callsArgWith(1, null);

    for (const walletId of ['requested-wallet', undefined]) {
      await new Promise<void>((resolve, reject) => {
        service._sendPushNotifications({ type: 'NewAddress', walletId }, err => err ? reject(err) : resolve());
      });
      assert.equal(send.lastCall.args[0].data.walletId, legacyHash(walletId || subscription.walletId));
      assert.equal(send.lastCall.args[0].data.copayerId, legacyHash(subscription.copayerId));
    }
  });
});
