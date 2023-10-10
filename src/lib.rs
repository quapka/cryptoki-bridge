extern crate libc;

pub(crate) mod communicator;
pub(crate) mod configuration_provider;
pub mod cryptoki;
mod cryptoki_error;
mod persistence;
pub(crate) mod state;

use crate::{
    communicator::Communicator,
    configuration_provider::root_configuration::RootConfiguration,
    state::{session::sessions::Sessions, slots::Slots, CryptokiState},
};
use lazy_static::lazy_static;
use std::sync::{Mutex, RwLock};
use tokio::runtime::Runtime;

lazy_static! {
    pub(crate) static ref STATE: RwLock<Option<CryptokiState>> = RwLock::new(None);
    pub(crate) static ref SLOTS: RwLock<Option<Slots>> = RwLock::new(None);
    pub(crate) static ref CONFIGURATION: RwLock<Option<RootConfiguration>> = RwLock::new(None);
    pub(crate) static ref SESSIONS: RwLock<Option<Sessions>> = RwLock::new(None);
    pub(crate) static ref RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);
    pub(crate) static ref COMMUNICATOR: Mutex<Option<Box<dyn Communicator>>> = Mutex::new(None);
}
