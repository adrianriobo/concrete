use crate::backends::core::private::crypto::gsw::GswCiphertext as ImplGswCiphertext;
use crate::specification::entities::{AbstractEntity, GgswCiphertextEntity, GswCiphertextEntity};
use crate::specification::entities::markers::{GgswCiphertextKind, GswCiphertextKind, BinaryKeyFlavor};
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use concrete_commons::parameters::{GlweDimension, PolynomialSize, DecompositionLevelCount, DecompositionBaseLog, LweDimension};

pub struct GswCiphertext32(ImplGswCiphertext<Vec<u32>, u32>);
impl AbstractEntity for GswCiphertext32{
    type Kind = GswCiphertextKind;
    type Representation = CpuStandard32;
}
impl GswCiphertextEntity for GswCiphertext32{
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}


pub struct GswCiphertext64(ImplGswCiphertext<Vec<u64>, u64>);
impl AbstractEntity for GswCiphertext64{
    type Kind = GswCiphertextKind;
    type Representation = CpuStandard64;
}
impl GswCiphertextEntity for GswCiphertext64{
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}
