use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    "The error used in the [`LweVectorEncryptionEngine`] trait.",
    LweVectorEncryptionError @
    LweDimensionMismatch => "Lwe dimensions of the key is incompatible with the output ciphertext.",
    CountMismatch => "Number of plaintext different from number of ciphertext."
}

/// A trait for engines which encrypt lwe ciphertexts.
pub trait LweVectorEncryptionEngine<Key, Input, Output>: AbstractEngine
where
    Key: LweSecretKeyEntity,
    Input: PlaintextVectorEntity<Representation = Key::Representation>,
    Output:
        LweCiphertextVectorEntity<Representation = Key::Representation, KeyFlavor = Key::KeyFlavor>,
{
    fn encrypt_lwe_vector(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    ) -> Result<(), LweVectorEncryptionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn encrypt_lwe_vector_unchecked(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    );
}
