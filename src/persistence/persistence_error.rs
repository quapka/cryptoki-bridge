use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum PersistenceError {
    SqliteError(sqlite::Error),
}

impl Error for PersistenceError {}

impl Display for PersistenceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PersistenceError")
    }
}

impl From<sqlite::Error> for PersistenceError {
    fn from(error: sqlite::Error) -> Self {
        Self::SqliteError(error)
    }
}
