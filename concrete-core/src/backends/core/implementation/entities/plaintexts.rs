use super::super::super::private::crypto::encoding::Plaintext as CorePlaintext;
use super::super::super::private::crypto::encoding::PlaintextList as CorePlaintextList;
use crate::specification::entities::{AbstractEntity, PlaintextEntity, PlaintextVectorEntity};
use crate::specification::entities::markers::{PlaintextKind, PlaintextVectorKind};
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use concrete_commons::parameters::PlaintextCount;

/// A structure representing a plaintext in 32 bits of precision.
pub struct Plaintext32(CorePlaintext<u32>);
impl AbstractEntity for Plaintext32{
    type Kind = PlaintextKind;
    type Representation = CpuStandard32;
}
impl PlaintextEntity for Plaintext32{}

/// A structure representing a plaintext in 64 bits of precision.
pub struct Plaintext64(CorePlaintext<u64>);
impl AbstractEntity for Plaintext64{
    type Kind = PlaintextKind;
    type Representation = CpuStandard64;
}
impl PlaintextEntity for Plaintext64{}

/// A structure representing a vector of plaintexts in 32 bits of precision.
pub struct PlaintextVector32(CorePlaintextList<u32>);
impl AbstractEntity for PlaintextVector32{
    type Kind = PlaintextVectorKind;
    type Representation = CpuStandard32;
}
impl PlaintextVectorEntity for PlaintextVector32{
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}

/// A structure representing a vector of plaintexts in 64 bits of precision.
pub struct PlaintextVector64(CorePlaintextList<u64>);
impl AbstractEntity for PlaintextVector64{
    type Kind = PlaintextVectorKind;
    type Representation = CpuStandard64;
}
impl PlaintextVectorEntity for PlaintextVector64{
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}
