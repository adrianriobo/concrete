use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweKeyswitchKey32, LweKeyswitchKey64, LweSecretKey32, LweSecretKey64,
};
use crate::backends::core::private::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::specification::engines::{
    LweKeyswitchKeyGenerationEngine, LweKeyswitchKeyGenerationError,
};
use crate::specification::entities::LweSecretKeyEntity;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

macro_rules! implem {
    ($Ksk:ident, $Sk:ident) => {
        impl LweKeyswitchKeyGenerationEngine<$Ksk, $Sk> for CoreEngine {
            fn generate_lwe_keyswitch_key(
                &mut self,
                input_key: &$Sk,
                output_key: &$Sk,
                decomposition_level_count: DecompositionLevelCount,
                decomposition_base_log: DecompositionBaseLog,
                noise: Variance,
            ) -> Result<$Ksk, LweKeyswitchKeyGenerationError<Self::EngineError>> {
                Ok(unsafe {
                    self.generate_lwe_keyswitch_key_unchecked(
                        input_key,
                        output_key,
                        decomposition_level_count,
                        decomposition_base_log,
                        noise,
                    )
                })
            }

            unsafe fn generate_lwe_keyswitch_key_unchecked(
                &mut self,
                input_key: &$Sk,
                output_key: &$Sk,
                decomposition_level_count: DecompositionLevelCount,
                decomposition_base_log: DecompositionBaseLog,
                noise: Variance,
            ) -> $Ksk {
                let mut ksk = ImplLweKeyswitchKey::allocate(
                    0,
                    decomposition_level_count,
                    decomposition_base_log,
                    input_key.lwe_dimension(),
                    output_key.lwe_dimension(),
                );
                ksk.fill_with_keyswitch_key(
                    &input_key.0,
                    &output_key.0,
                    noise,
                    &mut self.encryption_generator,
                );
                $Ksk(ksk)
            }
        }
    };
}
implem!(LweKeyswitchKey32, LweSecretKey32);
implem!(LweKeyswitchKey64, LweSecretKey64);
