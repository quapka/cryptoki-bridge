use std::env::VarError;

use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ConfigurationProviderError {
    #[error("Value was not set")]
    ValueNotSet(#[from] VarError),
    #[error("Value is in incorrect format")]
    InvalidFormat,
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

impl From<FromHexError> for ConfigurationProviderError {
    fn from(_value: FromHexError) -> Self {
        Self::InvalidFormat
    }
}
