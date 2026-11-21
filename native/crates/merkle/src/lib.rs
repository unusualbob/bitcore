use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub const HASH_BYTES: usize = 32;
pub type Hash = [u8; HASH_BYTES];

pub fn sha256d(bytes: &[u8]) -> Hash {
    Sha256::digest(Sha256::digest(bytes)).into()
}

fn parent(left: &Hash, right: &Hash) -> Hash {
    let mut pair = [0; 2 * HASH_BYTES];
    pair[..HASH_BYTES].copy_from_slice(left);
    pair[HASH_BYTES..].copy_from_slice(right);
    sha256d(&pair)
}

/// Appends Bitcoin's double-SHA256 Merkle levels, duplicating odd last nodes.
pub fn append_parents(tree: &mut Vec<Hash>) {
    let mut width = tree.len();
    let mut start = 0;
    while width > 1 {
        for i in (0..width).step_by(2) {
            let right = (i + 1).min(width - 1);
            tree.push(parent(&tree[start + i], &tree[start + right]));
        }
        start += width;
        width = width.div_ceil(2);
    }
}

/// Computes the Bitcoin Merkle root in place, retaining only one level.
pub fn root(leaves: &mut [Hash]) -> Option<Hash> {
    reduce(leaves, |left, right| parent(left, right.unwrap_or(left)))
}

pub const HASH160_BYTES: usize = 20;
pub type Hash160 = [u8; HASH160_BYTES];

pub fn hash160(bytes: &[u8]) -> Hash160 {
    Ripemd160::digest(Sha256::digest(bytes)).into()
}

/// BCH escrow hashes an unpaired node by itself.
pub fn escrow_root(leaves: &mut [Hash160]) -> Option<Hash160> {
    reduce(leaves, |left, right| {
        let mut pair = [0; 2 * HASH160_BYTES];
        pair[..HASH160_BYTES].copy_from_slice(left);
        if let Some(right) = right {
            pair[HASH160_BYTES..].copy_from_slice(right);
            hash160(&pair)
        } else {
            hash160(left)
        }
    })
}

fn reduce<T: Copy>(mut level: &mut [T], parent: impl Fn(&T, Option<&T>) -> T) -> Option<T> {
    while level.len() > 1 {
        for i in 0..level.len().div_ceil(2) {
            level[i] = parent(&level[2 * i], level.get(2 * i + 1));
        }
        let width = level.len().div_ceil(2);
        level = &mut level[..width];
    }
    level.first().copied()
}

/// Reconstructs a partial Merkle proof. Missing data and unused hashes go
/// back to the caller, which owns the public API's malformed-proof behavior.
pub fn partial_root(
    transactions: usize,
    hashes: &[Hash],
    flags: &[u8],
    digest: bool,
    mut on_match: impl FnMut(usize),
) -> Option<Hash> {
    let height = usize::BITS - transactions.checked_sub(1)?.leading_zeros();
    let mut proof = PartialProof {
        transactions,
        hashes,
        flags,
        digest,
        hash_index: 0,
        flag_index: 0,
    };
    let root = proof.traverse(height, 0, &mut on_match)?;
    (proof.hash_index == hashes.len()).then_some(root)
}

struct PartialProof<'a> {
    transactions: usize,
    hashes: &'a [Hash],
    flags: &'a [u8],
    digest: bool,
    hash_index: usize,
    flag_index: usize,
}

impl PartialProof<'_> {
    fn traverse(
        &mut self,
        height: u32,
        pos: usize,
        on_match: &mut impl FnMut(usize),
    ) -> Option<Hash> {
        let byte = self.flags.get(self.flag_index / 8)?;
        let expanded = (byte >> (self.flag_index % 8)) & 1 != 0;
        self.flag_index += 1;
        if height == 0 || !expanded {
            let hash = *self.hashes.get(self.hash_index)?;
            if height == 0 && expanded {
                on_match(self.hash_index);
            }
            self.hash_index += 1;
            return Some(hash);
        }
        let height = height - 1;
        let left = self.traverse(height, pos * 2, on_match)?;
        let right = if pos * 2 + 1 < self.transactions.div_ceil(1 << height) {
            self.traverse(height, pos * 2 + 1, on_match)?
        } else {
            left
        };
        Some(if self.digest {
            parent(&left, &right)
        } else {
            left
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash, append_parents};

    #[test]
    fn duplicates_odd_leaf_and_appends_levels_in_order() {
        let mut tree = vec![[0; 32], [1; 32], [2; 32]];
        append_parents(&mut tree);
        let hex = |text: &str| -> Hash {
            std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        };
        assert_eq!(
            tree,
            [
                [0; 32],
                [1; 32],
                [2; 32],
                hex("705ede9d42476fc3e5a978b042ce790a193678f46d19f47ec4ab46539c47b76d"),
                hex("992e801453af893c1b687d0ba6fa4293e388ee710793e6564acff430c632291d"),
                hex("d6384640762f797ede7e7f13839222f9452272809932cc6089f701331df4552d")
            ]
        );
    }
}
