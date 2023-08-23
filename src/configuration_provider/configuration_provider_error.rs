use std::{env::VarError, error::Error, fmt::Display};

use hex::FromHexError;

#[derive(Debug)]
pub(crate) enum ConfigurationProviderError {
    ValueNotSet,
    InvalidFormat,
}

impl Error for ConfigurationProviderError {}

impl Display for ConfigurationProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValueNotSet => write!(f, "Configuration error: Value was not set"),
            Self::InvalidFormat => write!(f, "Configuration error: Vale is in incorrect format"),
        }
    }
}

impl From<FromHexError> for ConfigurationProviderError {
    fn from(_value: FromHexError) -> Self {
        Self::InvalidFormat
    }
}

impl From<VarError> for ConfigurationProviderError {
    fn from(_value: VarError) -> Self {
        Self::ValueNotSet
    }
}
