import * as RBC from 'ripple-binary-codec';
import * as binary from 'ripple-binary-codec/dist/binary';
import { HashPrefix } from 'ripple-binary-codec/dist/hash-prefixes';
import * as xrpl from 'xrpl';
import { nativeCrypto } from '../../native';
import * as Utils from '../../utils';
import { sha512Half, supportsXrpSigning, trySignXrp } from '../../wallet-crypto';
import { BTCTxProvider } from '../btc';
import type { Key } from '../../types/derivation';

const TRANSACTION_ID_PREFIX = Buffer.from(HashPrefix.transactionID).toString('hex').toUpperCase();

export class XRPTxProvider {
  create(params: {
    recipients: Array<{ address: string; amount: string; tag?: number }>;
    tag?: number;
    from: string;
    invoiceID?: string;
    fee: number;
    feeRate: number;
    nonce: number;
    txType?: string;
    flags?: number | string;
  }) {
    const {
      recipients,
      tag,
      from,
      invoiceID,
      fee,
      nonce,
      // `params.type` is an old param to fallback to.
      // Changed to txType to re-use similar property name from other chains (e.g. EVM)
      txType = params['type'],
      flags,
    } = params;

    switch (txType?.toLowerCase()) {
      case 'payment':
      default:
        const { address, amount } = recipients[0];
        const _tag = recipients[0]?.tag || tag;
        const paymentTx: xrpl.Payment = {
          TransactionType: 'Payment',
          Account: from,
          Destination: address,
          Amount: amount.toString(),
          Fee: fee.toString(),
          Sequence: nonce,
          Flags: 2147483648 // tfFullyCanonicalSig - DEPRECATED but still here for backward compatibility
        };
        if (flags != null) {
          paymentTx.Flags = this.transformFlags<xrpl.PaymentFlagsInterface>(flags, 'payment');
          xrpl.setTransactionFlagsToNumber(paymentTx);
        }
        if (invoiceID) {
          paymentTx.InvoiceID = invoiceID;
        }
        if (_tag) {
          paymentTx.DestinationTag = _tag;
        }
        return xrpl.encode(paymentTx);
      case 'accountset':
        const accountSetTx: xrpl.AccountSet = {
          TransactionType: 'AccountSet',
          Account: from,
          Flags: this.transformFlags<xrpl.AccountSetFlagsInterface>(flags, 'accountset'),
          Fee: fee.toString(),
          Sequence: nonce
        };
        xrpl.setTransactionFlagsToNumber(accountSetTx);
        return xrpl.encode(accountSetTx);
      case 'accountdelete':
        const accountDeleteTx: xrpl.AccountDelete = {
          TransactionType: 'AccountDelete',
          Account: from,
          Destination: recipients[0].address,
          DestinationTag: recipients[0].tag,
          Fee: fee.toString(),
          Sequence: nonce
        };
        return xrpl.encode(accountDeleteTx);
    }
  }

  getSignatureObject(params: { tx: string; key: Key }) {
    const { tx, key } = params;
    const { signedTransaction, hash } = this.signTransaction(tx, key);
    return { signedTransaction, hash: hash ?? hashSignedTransaction(signedTransaction) };
  }

  getSignature(params: { tx: string; key: Key }): string {
    const { tx, key } = params;
    if (hasNativeXrpSigner() && this.getSignatureObject === getSignatureObject) {
      const result = this.signTransaction(tx, key);
      if (result.signature) return result.signature;
      return (xrpl.decode(result.signedTransaction) as unknown as xrpl.Transaction).TxnSignature;
    }
    const { signedTransaction } = this.getSignatureObject(params);
    const decoded = (xrpl.decode(signedTransaction) as any) as xrpl.Transaction;
    return decoded.TxnSignature;
  }

  getHash(params: { tx: string }): string {
    const { tx } = params;
    return this.sha512Half(TRANSACTION_ID_PREFIX + tx);
  }

  /**
   * Reads the fields BWS may mutate between proposal creation and publish out of a raw tx, to bind
   * txp.prePublishRaw to the proposal. For XRP that is only the account sequence/nonce (deferred-nonce).
   */
  getMutableFields(rawTx: string): { nonce?: number } {
    const txJSON = (xrpl.decode(rawTx) as any);
    return { nonce: txJSON?.Sequence != null ? Number(txJSON.Sequence) : undefined };
  }

  applySignature(params: { tx: string; signature: string; pubKey: string }): string {
    const { tx, signature, pubKey } = params;
    const txJSON = (xrpl.decode(tx) as any) as xrpl.Transaction;
    txJSON.TxnSignature = signature;
    txJSON.SigningPubKey = pubKey;
    const signedTx = xrpl.encode(txJSON);
    return signedTx;
  }

  sign(params: { tx: string; key: Key }): string {
    const { tx, key } = params;
    let signature: string;
    if (hasNativeXrpSigner() && this.getSignature === getSignature &&
        this.getSignatureObject === getSignatureObject && this.applySignature === applySignature) {
      const result = this.signTransaction(tx, key);
      if (result.signature) return result.signedTransaction;
      signature = (xrpl.decode(result.signedTransaction) as unknown as xrpl.Transaction).TxnSignature;
    } else {
      signature = this.getSignature({ tx, key });
    }
    return this.applySignature({ tx, signature, pubKey: key.pubKey });
  }

  sha512Half(hex: string): string {
    return sha512Half(hex);
  }

  private signTransaction(tx: string, key: Key): { signedTransaction: string; hash?: string; signature?: string } {
    const decoded = xrpl.decode(tx) as unknown as xrpl.Transaction;
    if (canSignXrp(decoded, key)) {
      xrpl.validate(decoded as unknown as Record<string, unknown>);
      const toSign = { ...decoded, SigningPubKey: key.pubKey.toUpperCase() };
      const signature = trySignXrp(xrpl.encodeForSigning(toSign), key.privKey);
      if (signature) {
        return { signedTransaction: xrpl.encode({ ...toSign, TxnSignature: signature }), signature };
      }
    }
    const signed = new xrpl.Wallet(key.pubKey.toUpperCase(), key.privKey.toUpperCase()).sign(decoded);
    return { signedTransaction: signed.tx_blob, hash: signed.hash };
  }

  transformSignatureObject(params: { obj: any }) {
    const { obj } = params;
    return new BTCTxProvider().transformSignatureObject({ obj });
  }

  getSighash(params: { tx: string; pubKey: string }) {
    const { tx, pubKey } = params;
    const decoded = RBC.decode(tx);
    decoded.SigningPubKey = pubKey;
    const encoded = binary.serializeObject(decoded, {
      prefix: HashPrefix.transactionSig,
      signingFieldsOnly: true
    }).toString('hex');
    return this.sha512Half(encoded);
  }

  private transformFlags<T extends xrpl.PaymentFlagsInterface>(flags: string | number, txType: 'payment'): T | number
  private transformFlags<T extends xrpl.AccountSetFlagsInterface>(flags: string | number, txType: 'accountset'): T | number
  private transformFlags<T extends xrpl.PaymentFlagsInterface | xrpl.AccountSetFlagsInterface>(flags: string | number, txType: 'payment' | 'accountset'): T | number {
    if (flags == null) {
      throw new Error('No XRP flag(s) provided');
    }
    if (typeof flags === 'number') {
      // Pass through numbers since they may be combined flags
      return flags;
    }
    const flagEnum = txType === 'payment' ? xrpl.PaymentFlags : xrpl.AccountSetTfFlags;
    return flags.split(',').reduce((acc, flag) => {
      const flagValue = Utils.normalizeXrpFlag(flag.trim(), flagEnum);
      acc[flagValue] = true;
      return acc;
    }, {} as T);
  }
}

const getSignatureObject = XRPTxProvider.prototype.getSignatureObject;
const getSignature = XRPTxProvider.prototype.getSignature;
const applySignature = XRPTxProvider.prototype.applySignature;

function hasNativeXrpSigner() {
  return typeof nativeCrypto?.cwcXrpSign === 'function' || typeof nativeCrypto?.ed25519Sign === 'function';
}

function canSignXrp(transaction: xrpl.Transaction, key: Key) {
  if (transaction.TxnSignature || 'Signers' in transaction || Object.values(transaction).some(value => value == null) ||
      typeof key?.pubKey !== 'string' || !/^(?:02|03|ed)[0-9a-f]{64}$/i.test(key.pubKey) ||
      !supportsXrpSigning(key.privKey)) return false;

  // Decoding canonicalizes issued values. Keep Wallet.sign for any Payment that
  // still needs its trailing-zero normalization or is missing a valid Amount.
  if (transaction.TransactionType !== 'Payment' || typeof transaction.Amount === 'string') return true;
  const value = transaction.Amount?.value;
  return typeof value === 'string' && !(value.includes('.') && value.endsWith('0'));
}

function hashSignedTransaction(transaction: string) {
  return sha512Half(TRANSACTION_ID_PREFIX + transaction);
}
