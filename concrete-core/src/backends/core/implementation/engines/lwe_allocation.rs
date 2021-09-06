use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::backends::core::private::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::specification::engines::{LweAllocationEngine, LweAllocationError};
use concrete_commons::parameters::LweDimension;

macro_rules! implem {
    ($Ciphertext:ident) => {
        impl LweAllocationEngine<$Ciphertext> for CoreEngine {
            fn allocate_lwe(
                &mut self,
                lwe_dimension: LweDimension,
            ) -> Result<$Ciphertext, LweAllocationError<Self::EngineError>> {
                Ok(unsafe { self.allocate_lwe_unchecked(lwe_dimension) })
            }

            unsafe fn allocate_lwe_unchecked(
                &mut self,
                lwe_dimension: LweDimension,
            ) -> $Ciphertext {
                $Ciphertext(ImplLweCiphertext::allocate(0, lwe_dimension.to_lwe_size()))
            }
        }
    };
}

implem!(LweCiphertext32);
implem!(LweCiphertext64);
