use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweSecretKey32, LweSecretKey64};
use crate::backends::core::private::crypto::secret::LweSecretKey as ImplLweSecretKey;
use crate::specification::engines::{LweAllocationError, LweSecretKeyGenerationEngine};
use concrete_commons::parameters::LweSize;

impl LweSecretKeyGenerationEngine<LweSecretKey32> for CoreEngine {
    fn generate_lwe_secret_key(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<LweSecretKey32, LweAllocationError<Self::EngineError>> {
        Ok(unsafe { self.generate_lwe_secret_key_unchecked(lwe_size) })
    }

    unsafe fn generate_lwe_secret_key_unchecked(&mut self, lwe_size: LweSize) -> LweSecretKey32 {
        LweSecretKey32(ImplLweSecretKey::generate_binary(
            lwe_size.to_lwe_dimension(),
            &mut self.secret_generator,
        ))
    }
}

impl LweSecretKeyGenerationEngine<LweSecretKey64> for CoreEngine {
    fn generate_lwe_secret_key(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<LweSecretKey64, LweAllocationError<Self::EngineError>> {
        Ok(unsafe { self.generate_lwe_secret_key_unchecked(lwe_size) })
    }

    unsafe fn generate_lwe_secret_key_unchecked(&mut self, lwe_size: LweSize) -> LweSecretKey64 {
        LweSecretKey64(ImplLweSecretKey::generate_binary(
            lwe_size.to_lwe_dimension(),
            &mut self.secret_generator,
        ))
    }
}
