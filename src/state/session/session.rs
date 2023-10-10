use std::{collections::HashMap, iter::Chain, sync::Arc, vec::IntoIter};

use aes::Aes128;
use dashmap::DashMap;
use openssl::hash::Hasher;
use rand::{rngs::OsRng, Rng};
use uuid::Uuid;

use crate::{
    communicator::{AuthResponse, GroupId, TaskId},
    cryptoki::bindings::CK_OBJECT_HANDLE,
    persistence::cryptoki_repo::CryptokiRepo,
    state::{
        object::{
            cryptoki_object::CryptokiObject, object_search::ObjectSearch,
            private_key_object::PrivateKeyObject, public_key_object::PublicKeyObject,
        },
        slots::TokenStore,
    },
};

/// Holds the current state of PKCS#11 lib
pub(crate) struct Session {
    /// Holds the object managed by functions C_Digest*
    hasher: Option<Hasher>,

    object_search: Option<ObjectSearch>,

    // TODO: cast to into_iter
    object_search_iterator: Option<Chain<IntoIter<CK_OBJECT_HANDLE>, IntoIter<CK_OBJECT_HANDLE>>>,

    // TODO: objects should be held by the token struct
    // TODO: also store token ID
    // TODO: RwLock
    handle_resolver: HandleResolver,
    token: TokenStore,

    encryptor: Option<Aes128>,

    signer: Option<Signer>,

    key_pair: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,

    cryptoki_repo: Arc<dyn CryptokiRepo>,
    ephemeral_objects: HashMap<Uuid, Arc<dyn CryptokiObject>>,
}

struct HandleResolver {
    object_handles: DashMap<Uuid, CK_OBJECT_HANDLE>,
    object_ids: DashMap<CK_OBJECT_HANDLE, Uuid>,
}

impl HandleResolver {
    pub(crate) fn new() -> Self {
        Self {
            object_handles: DashMap::new(),
            object_ids: DashMap::new(),
        }
    }

    fn generate_object_handle(&self) -> CK_OBJECT_HANDLE {
        let mut object_handle = OsRng.gen_range(0..CK_OBJECT_HANDLE::MAX);
        while self.object_ids.contains_key(&object_handle) {
            object_handle = OsRng.gen_range(0..CK_OBJECT_HANDLE::MAX);
        }

        object_handle
    }

    pub(crate) fn get_or_insert_object_handle(&self, object_id: Uuid) -> CK_OBJECT_HANDLE {
        let handle = self.object_handles.entry(object_id).or_insert_with(|| {
            let handle = self.generate_object_handle();
            self.object_ids.insert(handle, object_id);
            handle
        });
        *handle.value()
    }

    pub(crate) fn destroy_object_mapping(&self, handle: CK_OBJECT_HANDLE) -> Option<Uuid> {
        let Some(uuid) = self.object_ids.remove(&handle).map(|(_, uuid)| uuid) else {
            return None;
        };
        self.object_handles.remove(&uuid);
        Some(uuid)
    }

    pub(crate) fn get_object_id(&self, handle: CK_OBJECT_HANDLE) -> Option<Uuid> {
        self.object_ids.get(&handle).map(|x| *x.value())
    }
}
#[derive(Clone)]
pub(crate) struct Signer {
    pub key: Arc<dyn CryptokiObject>,
    pub response: Option<AuthResponse>,
    pub task_id: Option<TaskId>,
    pub auth_request_originator: Option<String>,
}
impl Signer {
    pub(crate) fn new(
        key: Arc<dyn CryptokiObject>,
        auth_request_originator: Option<String>,
    ) -> Self {
        Self {
            key,
            response: None,
            task_id: None,
            auth_request_originator,
        }
    }
}
impl Session {
    pub(crate) fn new(token: TokenStore, cryptoki_repo: Arc<dyn CryptokiRepo>) -> Self {
        // TODO: refactor
        let pubkey: GroupId = token.read().unwrap().get_public_key().into();
        let mut session = Self {
            hasher: None,
            object_search: None,
            token,
            encryptor: None,
            signer: None,
            object_search_iterator: None,
            key_pair: None,
            cryptoki_repo,
            handle_resolver: HandleResolver::new(),
            ephemeral_objects: HashMap::new(),
        };

        session.key_pair = Some(session.create_communicator_keypair(pubkey));
        session
    }
    pub fn get_keypair(&self) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        self.key_pair.unwrap()
    }
    pub fn get_hasher(&mut self) -> Option<Hasher> {
        self.hasher.take()
    }

    pub fn set_hasher(&mut self, hasher: Hasher) {
        self.hasher = Some(hasher)
    }

    pub fn set_object_search(&mut self, object_search: ObjectSearch) {
        self.object_search = Some(object_search);
    }

    pub fn get_object_search(&self) -> Option<&ObjectSearch> {
        self.object_search.as_ref()
    }

    pub fn init_object_search(&mut self, object_search: ObjectSearch) {
        self.object_search_iterator = None;
        self.object_search = Some(object_search);
    }

    pub fn reset_object_search(&mut self) {
        self.object_search_iterator = None;
        self.object_search = None;
    }

    pub fn create_object(&mut self, object: Arc<dyn CryptokiObject>) -> CK_OBJECT_HANDLE {
        // todo: error handling
        let object_id = self.cryptoki_repo.store_object(object).unwrap();
        self.handle_resolver.get_or_insert_object_handle(object_id)
    }

    pub fn create_ephemeral_object(&mut self, object: Arc<dyn CryptokiObject>) -> CK_OBJECT_HANDLE {
        let id = *object.get_id();
        self.ephemeral_objects.insert(id, object);
        self.handle_resolver.get_or_insert_object_handle(id)
    }

    // TODO: custom error
    pub fn destroy_object(
        &mut self,
        object_handle: &CK_OBJECT_HANDLE,
    ) -> Option<Arc<dyn CryptokiObject>> {
        let Some(object_id) = self
            .handle_resolver
            .destroy_object_mapping(object_handle.clone())
        else {
            return None;
        };
        let destroyed_object = self.ephemeral_objects.remove(&object_id);
        if destroyed_object.is_some() {
            return destroyed_object;
        }
        let destroyed_object = self.cryptoki_repo.destroy_object(object_id).unwrap();
        destroyed_object
    }

    pub(crate) fn get_object(
        &self,
        object_handle: CK_OBJECT_HANDLE,
    ) -> Option<Arc<dyn CryptokiObject>> {
        // TODO: error handling
        let Some(object_id) = self.handle_resolver.get_object_id(object_handle) else {
            return None;
        };
        let object = self.ephemeral_objects.get(&object_id);
        if object.is_some() {
            return object.cloned();
        }
        self.cryptoki_repo.get_object(object_id.clone()).unwrap()
    }

    pub(crate) fn get_token(&self) -> TokenStore {
        self.token.clone()
    }

    // TODO: return an error if search not innited
    pub fn get_filtered_handles(&mut self, object_count: usize) -> Vec<CK_OBJECT_HANDLE> {
        let Some(object_search) = self.object_search.as_ref() else {
            return vec![]; // TODO: return error
        };
        if self.object_search_iterator.is_none() {
            let ephemeral_objects = self
                .ephemeral_objects
                .iter()
                .filter(|(_, object)| object.does_template_match(object_search.get_template()))
                .map(|(id, _)| self.handle_resolver.get_or_insert_object_handle(*id))
                .collect::<Vec<CK_OBJECT_HANDLE>>()
                .into_iter();
            self.object_search_iterator = Some(
                self.cryptoki_repo
                    .get_objects(self.object_search.as_ref().unwrap())
                    .unwrap()
                    .iter()
                    .map(|object| {
                        self.handle_resolver
                            .get_or_insert_object_handle(object.get_id().clone())
                    })
                    .collect::<Vec<CK_OBJECT_HANDLE>>()
                    .into_iter()
                    .chain(ephemeral_objects),
            )
        }
        self.object_search_iterator
            .as_mut()
            .unwrap()
            .take(object_count)
            .collect()
    }

    pub fn set_encryptor(&mut self, encryptor: Aes128) {
        self.encryptor = Some(encryptor);
    }

    pub fn get_encryptor(&self) -> Option<Aes128> {
        self.encryptor.clone()
    }

    pub fn set_signer(&mut self, signer: Signer) {
        self.signer = Some(signer)
    }

    pub fn get_signer(&self) -> Option<Signer> {
        self.signer.clone()
    }

    pub fn store_signing_response(&mut self, response: AuthResponse) {
        let Some(ref mut signer) = self.signer else {
            return;
        };

        signer.response = Some(response);
    }

    pub fn get_signing_response(&self) -> Option<AuthResponse> {
        let Some(ref signer) = self.signer else {
            return None;
        };
        signer.response.clone()
    }

    pub fn set_signer_task_id(&mut self, task_id: TaskId) {
        let Some(ref mut signer) = self.signer else {
            return;
        };
        signer.task_id = Some(task_id)
    }
    pub fn get_signing_task_id(&self) -> Option<TaskId> {
        let Some(ref signer) = self.signer else {
            return None;
        };
        signer.task_id.clone()
    }

    pub fn create_communicator_keypair(
        &mut self,
        pubkey: GroupId,
    ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let mut pubkey_object = PublicKeyObject::new();
        pubkey_object.store_value(pubkey.clone());
        let pubkey_handle = self.create_ephemeral_object(Arc::new(pubkey_object));

        let mut private_key = PrivateKeyObject::new();
        private_key.store_value(pubkey.clone());
        let private_key_handle = self.create_ephemeral_object(Arc::new(private_key));
        (private_key_handle, pubkey_handle)
    }
}
