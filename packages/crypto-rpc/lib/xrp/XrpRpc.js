import EventEmitter from 'events';
import { createHash } from 'node:crypto';
import util from 'util';
import { xrpl } from '@bitpay-labs/crypto-wallet-core';
import promptly from 'promptly';
import { nativeCrypto } from '../native.js';
import { XrpClientAdapter } from './XrpClientAdapter.js';
import { walletFromSeed } from './wallet.js';

const passwordPromptAsync = util.promisify(promptly.password);
const MAX_NATIVE_ED25519_BYTES = 1232;
const MAX_NATIVE_XRP_BYTES = 4096;
// The XRPL transaction-ID domain is the four bytes "TXN\0".
const TRANSACTION_ID_PREFIX = Buffer.from('54584e00', 'hex');

function hashSignedTransaction(rawTx) {
  if (typeof rawTx === 'string' && rawTx.length > 0 && rawTx.length % 2 === 0 && !/[^0-9a-f]/i.test(rawTx)) {
    return createHash('sha512').update(TRANSACTION_ID_PREFIX).update(rawTx, 'hex').digest('hex').slice(0, 64).toUpperCase();
  }
  return xrpl.hashes.hashSignedTx(rawTx);
}

function signXrpMessage(sign, ed25519, secretKey, message) {
  if (ed25519) {
    const result = sign(secretKey, message);
    if (!Buffer.isBuffer(result) || result.length !== 96) throw new Error('Invalid native XRP Ed25519 result');
    return result.subarray(32);
  }
  const signature = sign(message, secretKey);
  if (signature === null) return;
  if (!Buffer.isBuffer(signature) || signature.length < 8 || signature.length > 72 ||
      signature[0] !== 0x30 || signature[1] !== signature.length - 2) {
    throw new Error('Invalid native XRP DER signature');
  }
  return signature;
}

function trySignPayment(wallet, prepared) {
  // Wallet.sign also handles issued-currency and multisign transactions. This
  // path covers only the unsigned XRP payments constructed by signTransaction.
  if (prepared?.TransactionType !== 'Payment' || typeof prepared.Amount !== 'string' ||
      prepared.TxnSignature != null || prepared.Signers != null) return;

  const { privateKey, publicKey } = wallet;
  const ed25519 = /^ED[0-9a-f]{64}$/i.test(privateKey);
  const signInline = ed25519 ? nativeCrypto?.ed25519Sign : nativeCrypto?.cwcXrpSign;
  if (typeof signInline !== 'function' || (!ed25519 && !/^00[0-9a-f]{64}$/i.test(privateKey))) return;

  const tx = Object.fromEntries(Object.entries(prepared).filter(([, value]) => value != null));
  xrpl.validate(tx);
  tx.SigningPubKey = publicKey;
  const message = Buffer.from(xrpl.encodeForSigning(tx), 'hex');
  if (!message.length) return;
  const maxInlineBytes = ed25519 ? MAX_NATIVE_ED25519_BYTES : MAX_NATIVE_XRP_BYTES;
  const sign = message.length <= maxInlineBytes ? signInline :
    (ed25519 ? nativeCrypto?.ed25519SignLarge : nativeCrypto?.cwcXrpSignLarge);
  if (typeof sign !== 'function') return;

  const secretKey = Buffer.from(privateKey.slice(2), 'hex');
  try {
    const signature = signXrpMessage(sign, ed25519, secretKey, message);
    if (!signature) return;
    tx.TxnSignature = signature.toString('hex').toUpperCase();
    const blob = xrpl.encode(tx);
    // Wallet.sign validates the encoded signed transaction when it computes
    // the hash. The RPC only returns the blob, but preserve that validation.
    xrpl.hashes.hashSignedTx(blob);
    return blob;
  } finally {
    secretKey.fill(0);
  }
}

export class XrpRpc {
  constructor(config) {
    this.config = config;
    const {
      protocol,
      host,
      port,
      address,
      useClientAdapter = true
    } = config;
    const connectionString = `${protocol}://${host}:${port}`;
    // Use client adapter to include implementations of ripple-lib Client methods as an extension to the xrpl Client
    this.rpc = useClientAdapter ? new XrpClientAdapter(connectionString) : new xrpl.Client(connectionString);
    this.address = address;
    this.emitter = new EventEmitter();
    this.connectionIdleTimeout = null;
    this.connectionIdleMs = config.connectionIdleMs || 120000;
    this.rpc.on('error', () => {}); // ignore rpc connection errors as we reconnect if nec each request
  }

  async asyncCall(method, args) {
    // clear idle timer if exists
    clearTimeout(this.connectionIdleTimeout);
    // reset idle timer
    this.connectionIdleTimeout = setTimeout(async () => {
      try {
        await this.rpc.disconnect();
      } catch {
        // ignore disconnection error on idle
      }
    }, this.connectionIdleMs);
    this.connectionIdleTimeout.unref();

    if (!this.rpc.isConnected()) {
      // if there is an error connecting, throw error and try again on next call
      await this.rpc.connect();
    }

    if (!Array.isArray(args)) args = [args];
    const result = await this.rpc[method](...args);
    return result;
  }

  async asyncRequest(method, args) {
    return this.asyncCall('request', Object.assign({ command: method }, args));
  }

  async unlockAndSendToAddress({ address, amount, secret }) {
    if (secret === undefined) {
      secret = await passwordPromptAsync('> ');
    }
    console.warn('Unlocking for a single transaction.');
    return await this.sendToAddress({ address, amount, secret });
  }

  async sendToAddress({ address, amount, passphrase, tag, invoiceID, secret }) {
    const rawTx = await this.signTransaction({ address, amount, passphrase, tag, invoiceID, secret });
    const txHash = await this.sendRawTransaction({ rawTx });
    return txHash;
  }

  async signTransaction({ address, amount, tag, invoiceID, secret }) {
    if (!secret) {
      const err = new Error('Secret not provided');
      err.conclusive = true; // used by server
      throw err;
    }
    const wallet = walletFromSeed(secret);
    const payment = {
      TransactionType: 'Payment',
      Account: wallet.address,
      Amount: xrpl.xrpToDrops(amount),
      Destination: address
    };
    if (tag) {
      payment.DestinationTag = tag;
    }
    if (invoiceID) {
      payment.InvoiceID = invoiceID;
    }
    const prepared = await this.asyncCall('autofill', payment);
    const blob = trySignPayment(wallet, prepared);
    if (blob) return blob;
    const signed = wallet.sign(prepared);
    return signed.tx_blob;
  }

  async sendRawTransactionMany({ rawTxArray }) {
    const resultArray = [];
    for (const rawTx of rawTxArray) {
      const emitData = { rawTx };
      try {
        const txHash = await this.sendRawTransaction({ rawTx });
        emitData.txid = txHash;
        resultArray.push(emitData);
        this.emitter.emit('success', emitData);
      } catch (e) {
        emitData.error = e;
        resultArray.push(emitData);
        this.emitter.emit('failure', emitData);
      }
    }
    return resultArray;
  }

  async unlockAndSendToAddressMany({ payToArray, secret }) {
    if (secret === undefined) {
      secret = await passwordPromptAsync('> ');
    }

    const resultArray = [];

    for (const payment of payToArray) {
      const { address, amount, id } = payment;
      const emitData = { address, amount, id };
      this.emitter.emit('attempt', emitData);
      try {
        const txid = await this.sendToAddress({ address, amount, secret });
        emitData.txid = txid;
        resultArray.push(emitData);
        this.emitter.emit('success', emitData);

        // do not await confirmations, the submitted txs are pending not confirmed
      } catch (e) {
        emitData.error = e;
        resultArray.push(emitData);
        this.emitter.emit('failure', emitData);
      }
    }
    return resultArray;
  }


  async getRawTransaction({ txid }) {
    try {
      const { result } = await this.asyncRequest('tx', { transaction: txid, binary: true });
      return result.tx;
    } catch (err) {
      if (err && err.data && err.data.error === 'txnNotFound') {
        return null;
      }
      throw err;
    }
  }

  async sendRawTransaction({ rawTx }) {
    const { result } = await this.asyncCall('submit', rawTx);
    const { accepted, engine_result_message, tx_json } = result;
    if (accepted) {
      return tx_json.hash;
    } else {
      throw new Error(engine_result_message);
    }
  }

  async decodeRawTransaction({ rawTx }) {
    const txJSON = xrpl.decode(rawTx);

    if (txJSON.TxnSignature) {
      txJSON.hash = hashSignedTransaction(rawTx);
    }

    return txJSON;
  }

  async estimateFee() {
    const { result } = await this.asyncRequest('fee');
    return result.drops.minimum_fee;
  }

  async getBalance({ address, ledgerIndex }) {
    const balance = await this.asyncCall('getXrpBalance', [address || this.address, { ledger_index: ledgerIndex }]);
    return parseFloat(balance);
  }

  async getBestBlockHash() {
    const tip = await this.getTip();
    return tip.hash;
  }

  async getTransaction({ txid }) {
    try {
      const { result } = await this.asyncRequest('tx', { transaction: txid });
      if (!result) {
        return null;
      }
      // Append Confirmations
      if (!result.ledger_index) {
        result.confirmations = 0;
      } else {
        const tip = await this.getTip();
        const height = tip.height;
        result.confirmations = height - result.ledger_index + 1; // Tip is considered confirmed
      }
      // Append BlockHash
      const { result: txBlock } = await this.asyncRequest('ledger', { ledger_index: result.ledger_index });
      result.blockHash = txBlock.ledger_hash;
      return result;
    } catch (err) {
      if (err && err.data && err.data.error === 'txnNotFound') {
        return null;
      }
      throw err;
    }
  }

  /**
   * Get all transactions for an account
   * @param {object} params
   * @param {string} params.address Account to get transactions for
   * @param {object} params.options See https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_tx/
   * @returns 
   */
  async getTransactions({ address, options }) {
    try {
      const { result } = await this.asyncRequest('account_tx', { account: address, ...options });
      return result;
    } catch (err) {
      if (err && err.data && err.data.error === 'actNotFound') {
        return [];
      }
      throw err;
    }
  }

  /**
   * Get block by hash or index
   * @param {object} params
   * @param {string} [params.hash] - The block hash
   * @param {number|string} [params.index] - The block index or 'latest'
   * @param {boolean} [params.transactions=true] - Whether to include transactions
   * @param {boolean} [params.expand=true] - Whether to expand transactions
   * @returns 
   */
  async getBlock({ hash, index, transactions = true, expand = true } = {}) {
    try {
      if (index === 'latest') {
        index = 'validated';
      }
      let result;
      if (hash) {
        ({ result } = await this._getBlockByHash({ hash, transactions, expand }));
      } else {
        ({ result } = await this._getBlockByIndex({ index, transactions, expand }));
      }
      return result;
    } catch (err) {
      if (err && err.data && err.data.error === 'lgrNotFound') {
        return null;
      }
      throw err;
    }
  }

  _getBlockByHash({ hash, transactions = true, expand = true }) {
    return this.asyncRequest('ledger', {
      ledger_hash: hash,
      transactions,
      expand
    });
  }

  _getBlockByIndex({ index = 'validated', transactions = true, expand = true }) {
    return this.asyncRequest('ledger', {
      ledger_index: index,
      transactions,
      expand
    });
  }

  async getConfirmations({ txid }) {
    return (await this.getTransaction({ txid })).confirmations;
  }

  async getTip() {
    const { result } = await this.asyncRequest('ledger', {
      ledger_index: 'validated'
    });
    const height = result.ledger_index;
    const hash = result.ledger_hash;
    return { height, hash };
  }

  async getTxOutputInfo() {
    return null;
  }

  async validateAddress({ address }) {
    return xrpl.isValidAddress(address);
  }

  async getAccountInfo({ address }) {
    try {
      const { result } = await this.asyncRequest('account_info', { account: address });
      return result;
    } catch (error) {
      if (error.data && error.data.error && error.data.error === 'actNotFound') {
        error.conclusive = true;
      }
      throw error;
    }
  }

  async getServerInfo() {
    const { result } = await this.asyncRequest('server_info');
    return result.info;
  }
}
