use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    "The error used in the [`GlweEncryptionEngine`] trait.",
    GlweEncryptionError @
    GlweDimensionMismatch => "Glwe dimensions of the key is incompatible with the output ciphertext.",
    PolynomialSizeMismatch => "Polynomial size of the key is incompatible with the output ciphertext."
}
pub trait GlweEncryptionEngine<Key, Input, Output>: AbstractEngine
where
    Key: GlweSecretKeyEntity,
    Input: PlaintextVectorEntity<Representation = Key::Representation>,
    Output: GlweCiphertextEntity<Representation = Key::Representation, KeyFlavor = Key::KeyFlavor>,
{
    fn encrypt_glwe(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    ) -> Result<(), GlweEncryptionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn encrypt_glwe_unchecked(
        &mut self,
        key: &Key,
        output: &mut Output,
        input: &Input,
        noise: Variance,
    );
}
