use sha2::{Digest, Sha256};

pub const HASH_BYTES: usize = 32;
pub type Hash = [u8; HASH_BYTES];

/// Appends Bitcoin's double-SHA256 Merkle levels, duplicating odd last nodes.
pub fn append_parents(tree: &mut Vec<Hash>) {
    let mut width = tree.len();
    let mut start = 0;
    let mut pair = [0; 2 * HASH_BYTES];
    while width > 1 {
        for i in (0..width).step_by(2) {
            let right = (i + 1).min(width - 1);
            pair[..HASH_BYTES].copy_from_slice(&tree[start + i]);
            pair[HASH_BYTES..].copy_from_slice(&tree[start + right]);
            tree.push(Sha256::digest(Sha256::digest(pair)).into());
        }
        start += width;
        width = width.div_ceil(2);
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
