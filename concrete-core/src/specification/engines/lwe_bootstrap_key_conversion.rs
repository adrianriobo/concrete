use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{AbstractEntity, LweBootstrapKeyEntity};

engine_error! {
    "The error used in the [`LweBootstrapKeyConversionEngine`] trait.",
    LweBootstrapKeyConversionError @
    DifferingLweDimension => "The two keys have incompatible lwe dimension.",
    DifferingGlweDimension => "The two keys have incompatible glwe dimension.",
    DifferingPolynomialSize => "The two keys have incompatible polynomial size.",
    DifferingDecompositionBaseLog => "The two keys have incompatible base logarithms.",
    DifferingDecompositionLevelCount => "The two keys have incompatible level counts."
}

pub trait LweBootstrapKeyConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweBootstrapKeyEntity,
    Output: LweBootstrapKeyEntity<
        InputKeyFlavor = Input::InputKeyFlavor,
        OutputKeyFlavor = Input::OutputKeyFlavor,
    >,
{
    fn convert_lwe_bootstrap_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweBootstrapKeyConversionError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, output: &mut Output, input: &Input);
}
