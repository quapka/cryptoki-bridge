use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum PersistenceError {
    RusqliteError(rusqlite::Error),
}

impl Error for PersistenceError {}

impl Display for PersistenceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PersistenceError")
    }
}

impl From<rusqlite::Error> for PersistenceError {
    fn from(value: rusqlite::Error) -> Self {
        Self::RusqliteError(value)
    }
}
