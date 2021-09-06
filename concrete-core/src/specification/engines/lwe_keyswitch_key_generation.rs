use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::markers::BinaryKeyFlavor;
use crate::specification::entities::{LweKeyswitchKeyEntity, LweSecretKeyEntity};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};

engine_error! {
    "The error used in the [`LweKeyswitchKeyGenerationEngine`] trait.",
    LweKeyswitchKeyGenerationError @
    MemoryExhausted => "Not enough memory left to allocate the entity.",
    NoiseTooSmall => "The variance parameter provided is too small.",
    DecompositionTooSmall => "The number of levels in the decomposition must be greater than one.",
    ZeroDecompositionBase => "The decomposition base log must be greater than zero."
}

pub trait LweKeyswitchKeyGenerationEngine<KeyswitchKey, SecretKey>: AbstractEngine
where
    KeyswitchKey: LweKeyswitchKeyEntity<KeyFlavor = BinaryKeyFlavor>,
    SecretKey: LweSecretKeyEntity<
        KeyFlavor = BinaryKeyFlavor,
        Representation = KeyswitchKey::Representation,
    >,
{
    fn generate_lwe_keyswitch_key(
        &mut self,
        input_key: &SecretKey,
        output_key: &SecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<KeyswitchKey, LweKeyswitchKeyGenerationError<Self::EngineError>>;

    /// # Safety
    /// Todo
    unsafe fn generate_lwe_keyswitch_key_unchecked(
        &mut self,
        input_key: &SecretKey,
        output_key: &SecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> KeyswitchKey;
}
