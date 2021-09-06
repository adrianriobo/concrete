use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
    LweSecretKeyEntity,
};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

engine_error! {
    "The error used in the [`LweBootstrapKeyGenerationEngine`] trait.",
    LweBootstrapKeyGenerationError @
    MemoryExhausted => "Not enough memory to allocate the entity.",
    NoiseTooSmall => "The variance parameter provided is too small.",
    DecompositionTooSmall => "The number of levels in the decomposition must be greater than one.",
    ZeroDecompositionBase => "The decomposition base log must be greater than zero."
}

/// A trait
pub trait LweBootstrapKeyGenerationEngine<Bsk, Lwesk, Glwesk>: AbstractEngine
where
    Bsk: LweBootstrapKeyEntity,
    Lwesk:
        LweSecretKeyEntity<KeyFlavor = Bsk::InputKeyFlavor, Representation = Bsk::Representation>,
    Glwesk:
        GlweSecretKeyEntity<KeyFlavor = Bsk::OutputKeyFlavor, Representation = Bsk::Representation>,
{
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &Lwesk,
        output_key: &Glwesk,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<Bsk, LweBootstrapKeyGenerationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &Lwesk,
        output_key: &Glwesk,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Bsk;
}
