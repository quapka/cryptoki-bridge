use thiserror::Error;

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("Rusqlite error occurred")]
    RusqliteError(#[from] rusqlite::Error),
}
