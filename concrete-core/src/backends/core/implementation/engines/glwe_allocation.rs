use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{GlweCiphertext32, GlweCiphertext64};
use crate::backends::core::private::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::specification::engines::{GlweAllocationEngine, GlweAllocationError};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

macro_rules! implem {
    ($Ciphertext:ident) => {
        impl GlweAllocationEngine<$Ciphertext> for CoreEngine {
            fn allocate_glwe(
                &mut self,
                glwe_dimension: GlweDimension,
                polynomial_size: PolynomialSize,
            ) -> Result<$Ciphertext, GlweAllocationError<Self::EngineError>> {
                Ok(unsafe { self.allocate_glwe_unchecked(glwe_dimension, polynomial_size) })
            }

            unsafe fn allocate_glwe_unchecked(
                &mut self,
                glwe_dimension: GlweDimension,
                polynomial_size: PolynomialSize,
            ) -> $Ciphertext {
                $Ciphertext(ImplGlweCiphertext::allocate(
                    0,
                    polynomial_size,
                    glwe_dimension.to_glwe_size(),
                ))
            }
        }
    };
}

implem!(GlweCiphertext32);
implem!(GlweCiphertext64);
