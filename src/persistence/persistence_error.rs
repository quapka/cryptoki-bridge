use std::sync::PoisonError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("Rusqlite error occurred")]
    RusqliteError(#[from] rusqlite::Error),
    #[error("Data inconsistency: {0}")]
    DataInconsistency(String),
    #[error("Poison error occurred")]
    SynchronizationElementPoisoned,
}

impl<S> From<PoisonError<S>> for PersistenceError {
    fn from(_value: PoisonError<S>) -> Self {
        Self::SynchronizationElementPoisoned
    }
}
