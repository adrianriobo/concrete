use crate::backends::core::private::crypto::secret::generators::{
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
    SecretRandomGenerator as ImplSecretRandomGenerator,
};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of fhe operations, due to the core implementation.
///
/// # Note:
///
/// There is currently no such case, as the core implementation is not expected to undergo some
/// major issues unrelated to fhe.
#[derive(Debug)]
pub enum CoreError {}
impl Display for CoreError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}
impl Error for CoreError {}

/// The main engine exposed by the core backend.
pub struct CoreEngine {
    secret_generator: ImplSecretRandomGenerator,
    encryption_generator: ImplEncryptionRandomGenerator,
}

impl AbstractEngineSeal for CoreEngine {}
impl AbstractEngine for CoreEngine {
    type EngineError = CoreError;

    fn new() -> Result<Self, Self::EngineError> {
        Ok(CoreEngine {
            secret_generator: ImplSecretRandomGenerator::new(None),
            encryption_generator: ImplEncryptionRandomGenerator::new(None),
        })
    }
}

mod glwe_allocation;
mod glwe_encryption;
mod glwe_sample_extraction;
mod glwe_secret_key_generation;
mod lwe_addition;
mod lwe_allocation;
mod lwe_bootstrap;
mod lwe_bootstrap_key_conversion;
mod lwe_bootstrap_key_generation;
mod lwe_cleartext_multiplication;
mod lwe_encryption;
mod lwe_keyswitch_key_generation;
mod lwe_multisum;
mod lwe_negation;
mod lwe_secret_key_generation;
