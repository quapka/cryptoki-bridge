use crate::{
    communicator::{
        communicator_error::CommunicatorError, group::Group, meesign::Meesign, AuthResponse,
        Communicator, GroupId, RequestData, TaskId,
    },
    configuration_provider::{
        controller_configuration::ControllerConfiguration, env_configuration::EnvConfiguration,
        root_configuration::RootConfiguration, ConfigurationProvider,
    },
    cryptoki::bindings::{CK_SESSION_HANDLE, CK_SLOT_ID, CK_TOKEN_INFO},
};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};
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
    ) -> Self {
        Self {
            sessions: Default::default(),
            communicator,
            runtime,
            slots: Slots::new(),
            configuration,
        }
    }

    pub(crate) fn get_token(&self, slot_id: &CK_SLOT_ID) -> Option<TokenStore> {
        self.slots.get_token(slot_id)
    }
}

#[cfg(not(feature = "mocked_meesign"))]
impl Default for CryptokiState {
    // TODO: just tmp, remove later, pls don't look
    fn default() -> Self {
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

        Self::new(Box::new(meesign), runtime, configuration)
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
        Self::new(Box::new(meesign), runtime, configuration)
    }
}
