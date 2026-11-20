use std::fmt;
use std::sync::OnceLock;

use secp256k1::{Secp256k1, SignOnly, VerifyOnly};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextRandomizationError;

impl fmt::Display for ContextRandomizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("could not obtain OS entropy to blind the secp256k1 context")
    }
}

impl std::error::Error for ContextRandomizationError {}

/// Shares the blinded context used for ECDSA signing and private-key multiplication.
pub fn signing_context() -> Result<&'static Secp256k1<SignOnly>, ContextRandomizationError> {
    static CONTEXT: OnceLock<Secp256k1<SignOnly>> = OnceLock::new();
    if let Some(context) = CONTEXT.get() {
        return Ok(context);
    }
    // Leave initialization retryable if the operating system cannot supply entropy.
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| ContextRandomizationError)?;
    Ok(CONTEXT.get_or_init(|| {
        let mut context = Secp256k1::signing_only();
        context.seeded_randomize(&seed);
        context
    }))
}

/// Shares the context for operations on public keys and signatures.
pub fn verification_context() -> &'static Secp256k1<VerifyOnly> {
    static CONTEXT: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CONTEXT.get_or_init(Secp256k1::verification_only)
}
