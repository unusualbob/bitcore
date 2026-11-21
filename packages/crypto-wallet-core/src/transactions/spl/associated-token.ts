import * as SolKit from '@solana/kit';
import * as Token from '@solana-program/token';
import { decodeBase58, encodeBase58 } from '../../base58';
import { nativeCrypto } from '../../native';

function encodeAddress(address: SolKit.Address) {
  if (typeof address === 'string' && address.length >= 32 && address.length <= 44) {
    const bytes = decodeBase58(address);
    if (bytes.length === 32) return bytes;
  }
  return SolKit.getAddressEncoder().encode(address);
}

export const findAssociatedTokenPda: typeof Token.findAssociatedTokenPda = async (seeds, config = {}) => {
  if (typeof nativeCrypto?.solAssociatedTokenAddress !== 'function' || config === null) {
    return Token.findAssociatedTokenPda(seeds, config);
  }

  const { programAddress = Token.ASSOCIATED_TOKEN_PROGRAM_ADDRESS } = config;
  const packed = Buffer.alloc(96);
  packed.set(encodeAddress(seeds.owner), 0);
  packed.set(encodeAddress(seeds.tokenProgram), 32);
  packed.set(encodeAddress(seeds.mint), 64);
  const program = encodeAddress(programAddress);
  const result = nativeCrypto.solAssociatedTokenAddress(packed, program);
  if (result === null) return Token.findAssociatedTokenPda(seeds, config);
  if (!Buffer.isBuffer(result) || result.length !== 33) throw new Error('Invalid native Solana PDA result');
  // The native result carries a 32-byte address followed by one unsigned bump byte.
  const address = encodeBase58(result.subarray(0, 32)) as SolKit.Address;
  const bump = result[32] as SolKit.ProgramDerivedAddress[1];
  return [address, bump];
};
