use std::io;

use aya::{maps::MapError, programs::ProgramError, BpfError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AnalyzerError>;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error(transparent)]
    BpfError(#[from] BpfError),
    #[error(transparent)]
    BpfProgramError(#[from] ProgramError),
    #[error(transparent)]
    BpfMapError(#[from] MapError),
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error("Application not found")]
    AppNotFound,
    #[error("Map error")]
    MapError,
}
