extern crate libc;

pub(crate) mod communicator;
pub(crate) mod configuration_provider;
pub mod cryptoki;
mod persistence;
pub(crate) mod state;

use crate::state::CryptokiState;
use lazy_static::lazy_static;
use std::sync::RwLock;

lazy_static! {
    pub(crate) static ref STATE: RwLock<Option<CryptokiState>> = RwLock::new(None);
}
