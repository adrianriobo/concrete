use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::backends::core::private::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::specification::engines::{LweAllocationEngine, LweAllocationError};
use concrete_commons::parameters::LweSize;

impl LweAllocationEngine<LweCiphertext32> for CoreEngine {
    /// # Example
    /// ```
    /// use concrete_commons::parameters::LweSize;
    /// use concrete_core::backends::core::implementation::engines::CoreEngine;
    /// use concrete_core::backends::core::implementation::entities::LweCiphertext32;
    /// let mut engine = CoreEngine;
    /// let ciphertext: LweCiphertext32 = engine.allocate_lwe(LweSize(10)).unwrap();
    /// ```
    fn allocate_lwe(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<LweCiphertext32, LweAllocationError<Self::EngineError>> {
        Ok(unsafe { self.allocate_lwe_unchecked(lwe_size) })
    }

    /// # Example
    /// ```
    /// use concrete_commons::parameters::LweSize;
    /// use concrete_core::backends::core::implementation::engines::CoreEngine;
    /// use concrete_core::backends::core::implementation::entities::LweCiphertext32;
    /// let mut engine = CoreEngine;
    /// let ciphertext: LweCiphertext32 = unsafe { engine.allocate_lwe_unchecked(LweSize(10)) };
    /// ```
    unsafe fn allocate_lwe_unchecked(&mut self, lwe_size: LweSize) -> LweCiphertext32 {
        LweCiphertext32(ImplLweCiphertext::allocate(0u32, lwe_size))
    }
}

impl LweAllocationEngine<LweCiphertext64> for CoreEngine {
    /// # Example
    /// ```
    /// use concrete_commons::parameters::LweSize;
    /// use concrete_core::backends::core::implementation::engines::CoreEngine;
    /// use concrete_core::backends::core::implementation::entities::LweCiphertext64;
    /// let mut engine = CoreEngine;
    /// let ciphertext: LweCiphertext64 = engine.allocate_lwe(LweSize(10)).unwrap();
    /// ```
    fn allocate_lwe(
        &mut self,
        lwe_size: LweSize,
    ) -> Result<LweCiphertext64, LweAllocationError<Self::EngineError>> {
        Ok(unsafe { self.allocate_lwe_unchecked(lwe_size) })
    }

    /// # Example
    /// ```
    /// use concrete_commons::parameters::LweSize;
    /// use concrete_core::backends::core::implementation::engines::CoreEngine;
    /// use concrete_core::backends::core::implementation::entities::LweCiphertext64;
    /// let mut engine = CoreEngine;
    /// let ciphertext: LweCiphertext64 = unsafe { engine.allocate_lwe_unchecked(LweSize(10)) };
    /// ```
    unsafe fn allocate_lwe_unchecked(&mut self, lwe_size: LweSize) -> LweCiphertext64 {
        LweCiphertext64(ImplLweCiphertext::allocate(0u64, lwe_size))
    }
}
