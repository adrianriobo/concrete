use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{
    LweAdditionEngine, LweAdditionError, LweInplaceAdditionEngine, LweInplaceAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweInplaceAdditionEngine<LweCiphertext32> for CoreEngine {
    fn inplace_add_lwe(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweInplaceAdditionError::LweDimensionMismatch);
        }
        Ok(unsafe { self.inplace_add_lwe_unchecked(output, input) })
    }

    unsafe fn inplace_add_lwe_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.update_with_add(&input.0);
    }
}

impl LweInplaceAdditionEngine<LweCiphertext64> for CoreEngine {
    fn inplace_add_lwe(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweInplaceAdditionError::LweDimensionMismatch);
        }
        Ok(unsafe { self.inplace_add_lwe_unchecked(output, input) })
    }

    unsafe fn inplace_add_lwe_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.update_with_add(&input.0);
    }
}
