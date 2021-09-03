use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::backends::core::private::crypto::encoding::{
    Cleartext as ImplCleartext, CleartextList as ImplCleartextList,
};
use crate::specification::entities::markers::{CleartextKind, CleartextVectorKind};
use crate::specification::entities::{AbstractEntity, CleartextEntity, CleartextVectorEntity};
use concrete_commons::parameters::CleartextCount;

/// A structure representing a cleartext in 32 bits of precision.
pub struct Cleartext32(pub(crate) ImplCleartext<u32>);
impl AbstractEntity for Cleartext32 {
    type Kind = CleartextKind;
    type Representation = CpuStandard32;
}
impl CleartextEntity for Cleartext32 {}

/// A structure representing a cleartext in 64 bits of precision.
pub struct Cleartext64(pub(crate) ImplCleartext<u64>);
impl AbstractEntity for Cleartext64 {
    type Kind = CleartextKind;
    type Representation = CpuStandard64;
}
impl CleartextEntity for Cleartext64 {}

/// A structure representing a vector of cleartexts in 32 bits of precision.
pub struct CleartextVector32(pub(crate) ImplCleartextList<Vec<u32>>);
impl AbstractEntity for CleartextVector32 {
    type Kind = CleartextVectorKind;
    type Representation = CpuStandard32;
}
impl CleartextVectorEntity for CleartextVector32 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

/// A structure representing a vector of cleartexts in 64 bits of precision.
pub struct CleartextVector64(pub(crate) ImplCleartextList<Vec<u64>>);

impl AbstractEntity for CleartextVector64 {
    type Kind = CleartextVectorKind;
    type Representation = CpuStandard64;
}
impl CleartextVectorEntity for CleartextVector64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}
