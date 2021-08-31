use crate::backends::core::private::crypto::secret::{GlweSecretKey as ImpGlweSecretKey};
use concrete_commons::key_kinds::BinaryKeyKind;
use crate::specification::entities::{AbstractEntity, GlweSecretKeyEntity};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use crate::specification::entities::markers::{BinaryKeyFlavor, GlweSecretKeyKind};
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};

pub struct GlweSecretKey32(ImpGlweSecretKey<BinaryKeyKind, Vec<u32>>);
impl AbstractEntity for GlweSecretKey32{
    type Kind = GlweSecretKeyKind;
    type Representation = CpuStandard32;
}
impl GlweSecretKeyEntity for GlweSecretKey32{
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.key_size()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}


pub struct GlweSecretKey64(ImpGlweSecretKey<BinaryKeyKind, Vec<u64>>);
impl AbstractEntity for GlweSecretKey64{
    type Kind = GlweSecretKeyKind;
    type Representation = CpuStandard64;
}
impl GlweSecretKeyEntity for GlweSecretKey64{

    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.key_size()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
