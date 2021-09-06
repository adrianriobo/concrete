use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{LweAdditionInplaceEngine, LweInplaceAdditionError};
use crate::specification::entities::LweCiphertextEntity;

macro_rules! implem {
    ($Ciphertext:ident) => {
        impl LweAdditionInplaceEngine<$Ciphertext> for CoreEngine {
            fn lwe_add_inplace(
                &mut self,
                output: &mut $Ciphertext,
                input: &$Ciphertext,
            ) -> Result<(), LweInplaceAdditionError<Self::EngineError>> {
                if output.lwe_dimension() != input.lwe_dimension() {
                    return Err(LweInplaceAdditionError::LweDimensionMismatch);
                }
                unsafe { self.lwe_add_inplace_unchecked(output, input) };
                Ok(())
            }

            unsafe fn lwe_add_inplace_unchecked(
                &mut self,
                output: &mut $Ciphertext,
                input: &$Ciphertext,
            ) {
                output.0.update_with_add(&input.0);
            }
        }
    };
}

implem!(LweCiphertext32);
implem!(LweCiphertext64);
