use std::{error::Error, fmt, sync::PoisonError};

use crate::cryptoki::bindings::{
    CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR,
    CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, CK_RV,
};

#[derive(Debug)]
pub(crate) enum CryptokiError {
    SynchronizationError,
    CryptokiNotInitialized,
    SessionHandleInvalid,
    InvalidArgument,
    FunctionNotSupported,
    OperationNotInitialized,
    ObjectHandleInvalid,
}
impl Error for CryptokiError {}
impl fmt::Display for CryptokiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptokiError")
    }
}
impl CryptokiError {
    pub(crate) fn into_ck_rv(self) -> CK_RV {
        match self {
            Self::SynchronizationError => CKR_GENERAL_ERROR as CK_RV,
            Self::CryptokiNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV,
            Self::SessionHandleInvalid => CKR_SESSION_HANDLE_INVALID as CK_RV,
            Self::InvalidArgument => CKR_ARGUMENTS_BAD as CK_RV,
            Self::FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            Self::OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED as CK_RV,
            Self::ObjectHandleInvalid => CKR_OBJECT_HANDLE_INVALID as CK_RV,
        }
    }
}

impl<S> From<PoisonError<S>> for CryptokiError {
    fn from(_value: PoisonError<S>) -> Self {
        Self::SynchronizationError
    }
}
