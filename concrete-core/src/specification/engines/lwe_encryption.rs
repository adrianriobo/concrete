use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity};
use concrete_commons::dispersion::Variance;

engine_error! {
    "The error used in the [`LweEncryptionEngine`] trait.",
    LweEncryptionError @
    LweDimensionMismatch => "Lwe dimensions of the key is incompatible with the output ciphertext."
}

/// A trait for engines which encrypt lwe ciphertexts.
pub trait LweEncryptionEngine<Key, Input, Output>: AbstractEngine
where
    Key: LweSecretKeyEntity,
    Input: PlaintextEntity<Representation = Key::Representation>,
    Output: LweCiphertextEntity<Representation = Key::Representation, KeyFlavor = Key::KeyFlavor>,
{
    fn encrypt_lwe(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    ) -> Result<(), LweEncryptionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn encrypt_lwe_unchecked(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    );
}
