use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{GlweCiphextext32, GlweCiphextext64};
use crate::backends::core::private::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::specification::engines::{GlweAllocationEngine, GlweAllocationError};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

impl GlweAllocationEngine<GlweCiphextext32> for CoreEngine {
    fn allocate_glwe(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphextext32, GlweAllocationError<Self::EngineError>> {
        Ok(unsafe { self.allocate_glwe_unchecked(glwe_dimension, polynomial_size) })
    }

    unsafe fn allocate_glwe_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphextext32 {
        GlweCiphextext32(ImplGlweCiphertext::allocate(
            0u32,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        ))
    }
}

impl GlweAllocationEngine<GlweCiphextext64> for CoreEngine {
    fn allocate_glwe(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweCiphextext64, GlweAllocationError<Self::EngineError>> {
        Ok(unsafe { self.allocate_glwe_unchecked(glwe_dimension, polynomial_size) })
    }

    unsafe fn allocate_glwe_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweCiphextext64 {
        GlweCiphextext64(ImplGlweCiphertext::allocate(
            0u64,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
        ))
    }
}
