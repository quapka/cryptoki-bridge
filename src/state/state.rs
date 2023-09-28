use crate::{
    communicator::{
        communicator_error::CommunicatorError, group::Group, meesign::Meesign, AuthResponse,
        Communicator, GroupId, RequestData, TaskId,
    },
    configuration_provider::{
        controller_configuration::ControllerConfiguration, env_configuration::EnvConfiguration,
        root_configuration::RootConfiguration, ConfigurationProvider,
    },
    cryptoki::{
        self,
        bindings::{CK_SESSION_HANDLE, CK_SLOT_ID, CK_TOKEN_INFO},
    },
    persistence::{cryptoki_repo::CryptokiRepo, sqlite_cryptoki_repo::SqliteCryptokiRepo},
};
use home::home_dir;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use tokio::runtime::Runtime;
use tonic::transport::Certificate;

use super::{
    session::{session::Session, sessions::Sessions},
    slots::{Slots, TokenStore},
};

pub(crate) struct CryptokiState {
    sessions: Sessions,
    communicator: Box<dyn Communicator>,
    runtime: Runtime,
    slots: Slots,
    configuration: RootConfiguration,
    cryptoki_repo: Arc<dyn CryptokiRepo>,
}

impl CryptokiState {
    pub(crate) fn create_session(&mut self, token: TokenStore) -> CK_SESSION_HANDLE {
        self.sessions.create_session(token)
    }

    pub(crate) fn close_session(&mut self, session_handle: &CK_SESSION_HANDLE) {
        self.sessions.close_session(session_handle)
    }

    pub(crate) fn get_session(
        &self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Option<RwLockReadGuard<Session>> {
        self.sessions.get_session(session_handle)
    }

    pub(crate) fn get_session_mut(
        &mut self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Option<RwLockWriteGuard<Session>> {
        self.sessions.get_session_mut(session_handle)
    }

    pub(crate) fn finalize(&mut self) {
        self.sessions.close_sessions()
    }

    pub(crate) async fn get_groups(&mut self) -> Result<Vec<Group>, CommunicatorError> {
        self.communicator.get_groups().await
    }

    pub(crate) fn get_groups_blocking(&mut self) -> Result<Vec<Group>, CommunicatorError> {
        self.runtime
            .block_on(async { self.communicator.get_groups().await })
    }

    pub(crate) async fn send_auth_request(
        &mut self,
        group_id: GroupId,
        data: RequestData,
    ) -> Result<TaskId, CommunicatorError> {
        self.communicator.send_auth_request(group_id, data).await
    }

    pub(crate) fn send_auth_request_blocking(
        &mut self,
        group_id: GroupId,
        data: RequestData,
    ) -> Result<TaskId, CommunicatorError> {
        self.runtime
            .block_on(async { self.communicator.send_auth_request(group_id, data).await })
    }

    pub(crate) async fn get_auth_response(
        &mut self,
        task_id: TaskId,
    ) -> Result<Option<AuthResponse>, CommunicatorError> {
        self.communicator.get_auth_response(task_id).await
    }

    pub(crate) fn get_auth_response_blocking(
        &mut self,
        task_id: TaskId,
    ) -> Result<Option<AuthResponse>, CommunicatorError> {
        self.runtime
            .block_on(async { self.communicator.get_auth_response(task_id).await })
    }
    pub(crate) fn send_signing_request_wait_for_response(
        &mut self,
        group_id: GroupId,
        data: RequestData,
    ) -> Result<Option<TaskId>, CommunicatorError> {
        self.runtime.block_on(async {
            let task_id = self.communicator.send_auth_request(group_id, data).await?;
            self.communicator.get_auth_response(task_id).await
        })
    }

    pub(crate) fn insert_token(&mut self, token: TokenStore) -> CK_SLOT_ID {
        self.slots.insert_token(token)
    }

    pub(crate) fn get_token_info(&self, slot_id: &CK_SLOT_ID) -> Option<CK_TOKEN_INFO> {
        self.slots.get_token_info(slot_id)
    }

    pub(crate) fn new(
        communicator: Box<dyn Communicator>,
        runtime: Runtime,
        configuration: RootConfiguration,
        cryptoki_repo: Arc<dyn CryptokiRepo>,
    ) -> Self {
        Self {
            sessions: Sessions::new(cryptoki_repo.clone()),
            communicator,
            runtime,
            slots: Slots::new(),
            configuration,
            cryptoki_repo,
        }
    }

    pub(crate) fn get_token(&self, slot_id: &CK_SLOT_ID) -> Option<TokenStore> {
        self.slots.get_token(slot_id)
    }
}

fn ensure_file_structure() -> Result<(), ()> {
    let cryptoki_directory_path = get_cryptoki_path();
    fs::create_dir(cryptoki_directory_path).unwrap();

    Ok(())
}
fn get_cryptoki_path() -> PathBuf {
    let Some(home_directory) = home_dir() else {
        todo!();
    };

    static CRYPTOKI_DIRECTORY_NAME: &str = ".cryptoki-bridge";
    let cryptoki_directory_path = home_directory.join(CRYPTOKI_DIRECTORY_NAME);
    cryptoki_directory_path
}

#[cfg(not(feature = "mocked_meesign"))]
impl Default for CryptokiState {
    // TODO: just tmp, remove later, pls don't look
    fn default() -> Self {
        ensure_file_structure().unwrap();
        let configuration = RootConfiguration::new()
            .add_provider(Box::new(ControllerConfiguration::new()))
            .add_provider(Box::new(EnvConfiguration::new()));
        let certificate_path = configuration
            .get_communicator_certificate_path()
            .unwrap()
            .expect("Couldn't get meesign CA certificate path");
        let cert = Certificate::from_pem(std::fs::read(certificate_path).unwrap());
        let runtime = Runtime::new().unwrap();
        let hostname = configuration
            .get_communicator_url()
            .unwrap()
            .expect("Coudln't get communicator URL");
        let meesign =
            runtime.block_on(async move { Meesign::new(hostname, 1337, cert).await.unwrap() });

        let cryptoki_repo = Arc::new(SqliteCryptokiRepo::new(get_cryptoki_path()));
        cryptoki_repo
            .create_tables()
            .expect("Couldn't crate tables");
        Self::new(Box::new(meesign), runtime, configuration, cryptoki_repo)
    }
}

#[cfg(feature = "mocked_meesign")]
impl Default for CryptokiState {
    fn default() -> Self {
        use crate::communicator::mocked_meesign::MockedMeesign;

        let runtime = Runtime::new().unwrap();
        let meesign = MockedMeesign::new("testgrp".into());
        let configuration = RootConfiguration::new()
            .add_provider(Box::new(ControllerConfiguration::new()))
            .add_provider(Box::new(EnvConfiguration::new()));
        let cryptoki_repo = Arc::new(SqliteCryptokiRepo::new(get_cryptoki_path()));
        cryptoki_repo
            .create_tables()
            .expect("Couldn't crate tables");
        Self::new(Box::new(meesign), runtime, configuration, cryptoki_repo)
    }
}
