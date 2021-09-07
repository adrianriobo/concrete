use concrete_commons::parameters::LweDimension;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweSecretKey32, LweSecretKey64};
use crate::backends::core::private::crypto::secret::LweSecretKey as ImplLweSecretKey;
use crate::specification::engines::{LweSecretKeyGenerationEngine, LweSecretKeyGenerationError};

macro_rules! implem {
    ($SecretKey:ident) => {
        impl LweSecretKeyGenerationEngine<$SecretKey> for CoreEngine {
            fn generate_lwe_secret_key(
                &mut self,
                lwe_dimension: LweDimension,
            ) -> Result<$SecretKey, LweSecretKeyGenerationError<Self::EngineError>> {
                Ok(unsafe { self.generate_lwe_secret_key_unchecked(lwe_dimension) })
            }

            unsafe fn generate_lwe_secret_key_unchecked(
                &mut self,
                lwe_dimension: LweDimension,
            ) -> $SecretKey {
                $SecretKey(ImplLweSecretKey::generate_binary(
                    lwe_dimension,
                    &mut self.secret_generator,
                ))
            }
        }
    };
}
implem!(LweSecretKey32);
implem!(LweSecretKey64);