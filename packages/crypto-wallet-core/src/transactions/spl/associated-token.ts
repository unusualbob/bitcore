import * as SolKit from '@solana/kit';
import * as Token from '@solana-program/token';
import { nativeCrypto } from '../../native';

export const findAssociatedTokenPda: typeof Token.findAssociatedTokenPda = async (seeds, config = {}) => {
  if (typeof nativeCrypto?.solAssociatedTokenAddress !== 'function' || config === null) {
    return Token.findAssociatedTokenPda(seeds, config);
  }

  const { programAddress = Token.ASSOCIATED_TOKEN_PROGRAM_ADDRESS } = config;
  const { encode } = SolKit.getAddressEncoder();
  const packed = Buffer.alloc(96);
  packed.set(encode(seeds.owner), 0);
  packed.set(encode(seeds.tokenProgram), 32);
  packed.set(encode(seeds.mint), 64);
  const program = encode(programAddress);
  const result = nativeCrypto.solAssociatedTokenAddress(packed, program);
  if (result === null) return Token.findAssociatedTokenPda(seeds, config);
  if (!Buffer.isBuffer(result) || result.length !== 33) throw new Error('Invalid native Solana PDA result');
  const address = [SolKit.getAddressDecoder().decode(result.subarray(0, 32)), result[32]];
  SolKit.assertIsProgramDerivedAddress(address);
  return address;
};
