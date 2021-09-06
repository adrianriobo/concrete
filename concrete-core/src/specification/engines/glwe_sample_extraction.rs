use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GlweCiphertextEntity, LweCiphertextEntity};
use concrete_commons::parameters::MonomialDegree;

engine_error! {
    "The error used in the [`GlweSampleExtractionEngine`] trait.",
    GlweSampleExtractionError @
    SizeMismatch => "The sizes of the output lwe does not match the size of the input glwe."
}

/// A trait for engines which glwe sample extraction.
pub trait GlweSampleExtractionEngine<Input, Output>: AbstractEngine
where
    Input: GlweCiphertextEntity,
    Output:
        LweCiphertextEntity<KeyFlavor = Input::KeyFlavor, Representation = Input::Representation>,
{
    fn glwe_sample_extract(
        &mut self,
        output: &mut Output,
        input: &Input,
        nth: MonomialDegree,
    ) -> Result<(), GlweSampleExtractionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn glwe_sample_extract_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
        nth: MonomialDegree,
    );
}
