use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::markers::BinaryKeyFlavor;
use crate::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

engine_error! {
    "The error used in the [`LweBootstrapEngine`] trait.",
    LweBootstrapError @
    InputDimensionMismatch => "Input ciphertext and key lwe dimension are different",
    PolynomialSizeMismatch => "Accumulator and key polynomial size are different",
    AccumulatorDimensionMismatch => "Accumulator and key glwe dimension are different",
    OutputDimensionMismatch => "Output and key  dimension are different"
}

/// A trait
// Todo: Ideally, the bsk representation should be same as ciphertext.
pub trait LweBootstrapEngine<BootstrapKey, Ciphertext, Accumulator>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    Accumulator: GlweCiphertextEntity<
        KeyFlavor = Ciphertext::KeyFlavor,
        Representation = Ciphertext::Representation,
    >,
    BootstrapKey:
        LweBootstrapKeyEntity<InputKeyFlavor = BinaryKeyFlavor, OutputKeyFlavor = BinaryKeyFlavor>,
{
    fn lwe_bootstrap(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    ) -> Result<(), LweBootstrapError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_bootstrap_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Ciphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    );
}
