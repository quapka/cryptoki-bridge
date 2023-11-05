use std::{collections::HashMap, sync::Arc};

use rand::{rngs::OsRng, Rng};

use crate::{
    cryptoki::bindings::CK_SESSION_HANDLE, persistence::cryptoki_repo::CryptokiRepo,
    state::slots::TokenStore,
};

use super::session::Session;

pub(crate) struct Sessions {
    sessions: HashMap<CK_SESSION_HANDLE, Session>,
    cryptoki_repo: Arc<dyn CryptokiRepo>,
}

impl Sessions {
    pub(crate) fn new(cryptoki_repo: Arc<dyn CryptokiRepo>) -> Self {
        Self {
            sessions: HashMap::new(),
            cryptoki_repo,
        }
    }
    fn generate_session_handle(&self) -> CK_SESSION_HANDLE {
        OsRng.gen_range(0..CK_SESSION_HANDLE::MAX)
    }

    pub(crate) fn create_session(&mut self, token: TokenStore) -> CK_SESSION_HANDLE {
        let new_session_state = Session::new(token, self.cryptoki_repo.clone());
        let mut session_handle = self.generate_session_handle();
        while self.sessions.contains_key(&session_handle) {
            session_handle = self.generate_session_handle();
        }
        self.sessions.insert(session_handle, new_session_state);

        session_handle
    }

    pub(crate) fn close_session(&mut self, session_handle: &CK_SESSION_HANDLE) {
        self.sessions.remove(session_handle);
        self.sessions.shrink_to_fit();
    }

    pub(crate) fn get_session(&self, session_handle: &CK_SESSION_HANDLE) -> Option<&Session> {
        self.sessions.get(session_handle)
    }

    pub(crate) fn get_session_mut(
        &mut self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Option<&mut Session> {
        self.sessions.get_mut(session_handle)
    }

    pub(crate) fn close_sessions(&mut self) {
        self.sessions.clear();
        self.sessions.shrink_to_fit();
    }
}
