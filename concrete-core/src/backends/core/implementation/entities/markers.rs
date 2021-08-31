use crate::specification::entities::markers::seal::EntityRepresentationMarkerSealed;
use crate::specification::entities::markers::EntityRepresentationMarker;

/// An entity representation kind for types in the cpu memory, in the standard domain, in 32bits.
#[derive(Clone, Debug)]
pub struct CpuStandard32;
impl EntityRepresentationMarkerSealed for CpuStandard32{}
impl EntityRepresentationMarker for CpuStandard32{}

/// An entity representation kind for types in the cpu memory, in the standard domain, in 64bits.
#[derive(Clone, Debug)]
pub struct CpuStandard64;
impl EntityRepresentationMarkerSealed for CpuStandard64{}
impl EntityRepresentationMarker for CpuStandard64{}

/// An entity representation kind for types in the cpu memory, in the fourier domain, in 64bits.
#[derive(Clone, Debug)]
pub struct CpuFourier64;
impl EntityRepresentationMarkerSealed for CpuFourier64{}
impl EntityRepresentationMarker for CpuFourier64{}
