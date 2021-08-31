use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::{AbstractEngine};
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of fhe operations, due to the core implementation.
///
/// # Note:
///
/// There is currently no such case, as the core implementation is not expected to undergo some
/// major issues unrelated to fhe.
#[derive(Debug)]
pub enum EngineError {}

impl Display for EngineError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}

impl Error for EngineError {}

/// The main engine exposed by the core backend.
pub struct CoreEngine {}

impl AbstractEngineSeal for CoreEngine {}
impl AbstractEngine for CoreEngine {
    type EngineError = EngineError;
}
