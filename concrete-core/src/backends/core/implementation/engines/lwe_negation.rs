use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{LweNegationInplaceEngine, LweNegationInplaceError};

macro_rules! implem {
    ($Ciphertext:ident) => {
        impl LweNegationInplaceEngine<$Ciphertext> for CoreEngine {
            fn lwe_neg_inplace(
                &mut self,
                input: &mut $Ciphertext,
            ) -> Result<(), LweNegationInplaceError<Self::EngineError>> {
                unsafe { self.lwe_neg_inplace_unchecked(input) };
                Ok(())
            }

            unsafe fn lwe_neg_inplace_unchecked(&mut self, input: &mut $Ciphertext) {
                input.0.update_with_neg();
            }
        }
    };
}

implem!(LweCiphertext32);
implem!(LweCiphertext64);
