use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    CleartextVectorEntity, LweCiphertextEntity, LweCiphertextVectorEntity, PlaintextEntity,
};

engine_error! {
    "The error used in the [`LweMultisumEngine`] trait.",
    LweMultisumError @
    LweDimensionMismatch => "Output and inputs have different lwe dimension.",
    VectorCountMismatch => "The size of the weight vector is different from the size of the inputs vector"

}
pub trait LweMultisumEngine<Output, Inputs, Weights, Bias>: AbstractEngine
where
    Output: LweCiphertextEntity,
    Inputs: LweCiphertextVectorEntity<
        Representation = Output::Representation,
        KeyFlavor = Output::KeyFlavor,
    >,
    Weights: CleartextVectorEntity<Representation = Output::Representation>,
    Bias: PlaintextEntity<Representation = Output::Representation>,
{
    fn lwe_multisum(
        &mut self,
        output: &mut Output,
        inputs: &Inputs,
        weights: &Weights,
        bias: &Bias,
    ) -> Result<(), LweMultisumError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn lwe_multisum_unchecked(
        &mut self,
        output: &mut Output,
        inputs: &Inputs,
        weights: &Weights,
        bias: &Bias,
    );
}
