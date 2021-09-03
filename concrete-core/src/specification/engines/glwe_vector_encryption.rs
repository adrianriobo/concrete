use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    "The error used in the [`GlweVectorEncryptionEngine`] trait.",
    GlweVectorEncryptionError @
    GlweDimensionMismatch => "Glwe dimensions of the key is incompatible with the output ciphertext.",
    PolynomialSizeMismatch => "Polynomial size of the key is incompatible with the output ciphertext.",
    CountMismatch => "Number of plaintext different from number of ciphertext."
}
pub trait GlweVectorEncryptionEngine<Key, Input, Output>: AbstractEngine
where
    Key: GlweSecretKeyEntity,
    Input: PlaintextVectorEntity<Representation = Key::Representation>,
    Output: GlweCiphertextVectorEntity<
        Representation = Key::Representation,
        KeyFlavor = Key::KeyFlavor,
    >,
{
    fn encrypt_glwe_vector(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    ) -> Result<(), GlweVectorEncryptionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn encrypt_glwe_vector_unchecked(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    );
}
