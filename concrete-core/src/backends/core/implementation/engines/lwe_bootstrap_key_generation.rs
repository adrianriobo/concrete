use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{GlweSecretKey32, LweSecretKey32, LweBootstrapKey32, LweBootstrapKey64, LweSecretKey64, GlweSecretKey64};
use crate::backends::core::private::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::specification::engines::{LweBootstrapKeyGenerationEngine, LweBootstrapKeyGenerationError};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

impl LweBootstrapKeyGenerationEngine<LweBootstrapKey32, LweSecretKey32, GlweSecretKey32>
    for CoreEngine
{
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey32, LweBootstrapKeyGenerationError<Self::EngineError>> {
        if decomposition_base_log.0 == 0{
            return Err(LweBootstrapKeyGenerationError::ZeroDecompositionBase);
        }
        if decomposition_level_count.0 <= 1 {
            return Err(LweBootstrapKeyGenerationError::DecompositionTooSmall);
        }
        if noise.0 == 0.0{
            return Err(LweBootstrapKeyGenerationError::NoiseTooSmall)
        }
        Ok(unsafe {
            self.generate_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweBootstrapKey32 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0u32,
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweBootstrapKey32(
            key
        )
    }
}

impl LweBootstrapKeyGenerationEngine<LweBootstrapKey64, LweSecretKey64, GlweSecretKey64>
for CoreEngine
{
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey64, LweBootstrapKeyGenerationError<Self::EngineError>> {
        if decomposition_base_log.0 == 0{
            return Err(LweBootstrapKeyGenerationError::ZeroDecompositionBase);
        }
        if decomposition_level_count.0 <= 1 {
            return Err(LweBootstrapKeyGenerationError::DecompositionTooSmall);
        }
        if noise.0 == 0.0{
            return Err(LweBootstrapKeyGenerationError::NoiseTooSmall)
        }
        Ok(unsafe {
            self.generate_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweBootstrapKey64 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0u64,
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweBootstrapKey64(
            key
        )
    }
}
