import { hash } from 'crypto';
import { Libs } from '../providers/libs';
import { BitcoinBlockType, BitcoinTransaction } from '../types/namespaces/Bitcoin';

interface BufferWriter {
  bufLen: number;
}

interface WireTransaction extends BitcoinTransaction {
  inputs: (BitcoinTransaction['inputs'][number] & { getWitnesses(): Buffer[] })[];
  _getHash(): Buffer;
  hasWitnesses(): boolean;
  toBuffer(noWitness?: boolean): Buffer;
  toBufferWriter(writer: BufferWriter): BufferWriter;
}

interface WireBlock extends BitcoinBlockType {
  header: BitcoinBlockType['header'] & { toBuffer(): Buffer };
  toBufferWriter(): BufferWriter;
}

export type UtxoTransactionMetadata = ReadonlyMap<BitcoinTransaction, { txid: string; size: number }>;

function compactSizeWidth(length: number): number {
  if (length < 253) return 1;
  if (length <= 0xffff) return 3;
  if (length <= 0xffffffff) return 5;
  return 9;
}

function getWitnessSize(tx: WireTransaction): number | undefined {
  // BTC, LTC and DOGE add the marker/flag and one CompactSize-prefixed
  // witness stack per input, including an empty stack for legacy inputs.
  let size = 2;
  for (const input of tx.inputs) {
    const witnesses = input.getWitnesses();
    if (!Array.isArray(witnesses)) {
      return undefined;
    }
    size += compactSizeWidth(witnesses.length);
    for (const witness of witnesses) {
      if (!(witness instanceof Uint8Array)) {
        return undefined;
      }
      size += compactSizeWidth(witness.length) + witness.length;
    }
  }
  return size;
}

function getWireLibrary(chain: string) {
  switch (chain) {
    case 'BTC':
    case 'BCH':
    case 'LTC':
    case 'DOGE':
      return Libs.get(chain)?.lib;
    default:
      return undefined;
  }
}

export function prepareUtxoTransactions(txs: BitcoinTransaction[], chain: string): UtxoTransactionMetadata {
  const metadata = new Map<BitcoinTransaction, { txid: string; size: number }>();
  const lib = getWireLibrary(chain);
  if (!lib) {
    return metadata;
  }

  const prototype = lib.Transaction.prototype;
  const witnessCapable = chain !== 'BCH';
  for (const tx of txs as WireTransaction[]) {
    // Preserve the hash and serialization of structural callers and subclasses.
    if (
      Object.getPrototypeOf(tx) !== prototype ||
      Object.prototype.hasOwnProperty.call(tx, 'hash') ||
      tx._getHash !== prototype._getHash ||
      tx.toBuffer !== prototype.toBuffer ||
      tx.toBufferWriter !== prototype.toBufferWriter
    ) {
      continue;
    }

    const bytes = witnessCapable ? tx.toBuffer(true) : tx.toBuffer();
    const witnessSize = witnessCapable && tx.hasWitnesses() ? getWitnessSize(tx) : 0;
    const size = witnessSize === undefined ? tx.toBuffer().length : bytes.length + witnessSize;
    const digest = hash('sha256', hash('sha256', bytes, 'buffer'), 'buffer');
    metadata.set(tx, { txid: digest.reverse().toString('hex'), size });
  }
  return metadata;
}

export function getUtxoBlockSize(block: BitcoinBlockType, chain: string, metadata?: UtxoTransactionMetadata): number {
  const lib = getWireLibrary(chain);
  const prototype = lib?.Block.prototype;
  const wireBlock = block as WireBlock;
  if (
    !prototype ||
    Object.getPrototypeOf(block) !== prototype ||
    block.toBuffer !== prototype.toBuffer ||
    wireBlock.toBufferWriter !== prototype.toBufferWriter
  ) {
    return block.toBuffer().length;
  }

  if (metadata) {
    // All four block writers serialize the full header (including DOGE AuxPow),
    // a CompactSize transaction count, and the full encoding of each transaction.
    let size = wireBlock.header.toBuffer().length + compactSizeWidth(block.transactions.length);
    for (const tx of block.transactions) {
      const prepared = metadata.get(tx);
      if (!prepared) {
        return wireBlock.toBufferWriter().bufLen;
      }
      size += prepared.size;
    }
    return size;
  }
  return wireBlock.toBufferWriter().bufLen;
}
