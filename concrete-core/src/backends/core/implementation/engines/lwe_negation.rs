use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{LweNegationInplaceEngine, LweNegationInplaceError};

impl LweNegationInplaceEngine<LweCiphertext32> for CoreEngine {
    fn lwe_neg_inplace(
        &mut self,
        input: &mut LweCiphertext32,
    ) -> Result<(), LweNegationInplaceError<Self::EngineError>> {
        unsafe { self.lwe_neg_inplace_unchecked(input) };
        Ok(())
    }

    unsafe fn lwe_neg_inplace_unchecked(&mut self, input: &mut LweCiphertext32) {
        input.0.update_with_neg();
    }
}

impl LweNegationInplaceEngine<LweCiphertext64> for CoreEngine {
    fn lwe_neg_inplace(
        &mut self,
        input: &mut LweCiphertext64,
    ) -> Result<(), LweNegationInplaceError<Self::EngineError>> {
        unsafe { self.lwe_neg_inplace_unchecked(input) };
        Ok(())
    }

    unsafe fn lwe_neg_inplace_unchecked(&mut self, input: &mut LweCiphertext64) {
        input.0.update_with_neg();
    }
}
