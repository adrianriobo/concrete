use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{LweAdditionInplaceEngine, LweInplaceAdditionError};
use crate::specification::entities::LweCiphertextEntity;

impl LweAdditionInplaceEngine<LweCiphertext32> for CoreEngine {
    fn lwe_add_inplace(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.lwe_add_inplace_unchecked(output, input) };
        Ok(())
    }

    unsafe fn lwe_add_inplace_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.update_with_add(&input.0);
    }
}

impl LweAdditionInplaceEngine<LweCiphertext64> for CoreEngine {
    fn lwe_add_inplace(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.lwe_add_inplace_unchecked(output, input) };
        Ok(())
    }

    unsafe fn lwe_add_inplace_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.update_with_add(&input.0);
    }
}
