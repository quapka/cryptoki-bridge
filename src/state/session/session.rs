use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    vec::IntoIter,
};

use aes::Aes128;
use openssl::hash::Hasher;
use rand::{rngs::OsRng, Rng};

use crate::{
    communicator::{AuthResponse, GroupId, TaskId},
    cryptoki::bindings::CK_OBJECT_HANDLE,
    state::{
        object::{
            cryptoki_object::CryptokiArc, object_search::ObjectSearch,
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

    object_search_iterator: Option<IntoIter<CK_OBJECT_HANDLE>>,

    // TODO: objects should be held by the token struct
    objects: HashMap<CK_OBJECT_HANDLE, CryptokiArc>,

    token: TokenStore,

    encryptor: Option<Aes128>,

    signer: Option<Signer>,

    key_pair: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,
}

#[derive(Clone)]
pub(crate) struct Signer {
    pub key: CryptokiArc,
    pub response: Option<AuthResponse>,
    pub task_id: Option<TaskId>,
}
impl Signer {
    pub(crate) fn new(key: CryptokiArc) -> Self {
        Self {
            key,
            response: None,
            task_id: None,
        }
    }
}
impl Session {
    pub(crate) fn new(token: TokenStore) -> Self {
        // TODO: refactor
        let pubkey: GroupId = token.read().unwrap().get_public_key().into();
        let mut session = Self {
            hasher: None,
            object_search: None,
            objects: Default::default(),
            token,
            encryptor: None,
            signer: None,
            object_search_iterator: None,
            key_pair: None,
        };

        session.key_pair = Some(session.create_communicator_keypair(pubkey));
        session
    }
    pub fn get_keypair(&self) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        self.key_pair.unwrap()
    }
    pub fn get_hasher_mut(&mut self) -> Option<&mut Hasher> {
        self.hasher.as_mut()
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

    pub fn create_object(&mut self, object: CryptokiArc) -> CK_OBJECT_HANDLE {
        let object_handle = self.generate_object_handle();

        let _ = self.objects.insert(object_handle, object);
        object_handle
    }

    // TODO: custom error
    pub fn destroy_object(&mut self, object_handle: &CK_OBJECT_HANDLE) -> Option<CryptokiArc> {
        // todo: are we sure this is the only arc?
        self.objects.remove(object_handle)
    }

    pub(crate) fn get_object(&self, object_handle: CK_OBJECT_HANDLE) -> Option<CryptokiArc> {
        self.objects.get(&object_handle).cloned()
    }

    fn generate_object_handle(&self) -> CK_OBJECT_HANDLE {
        let mut object_handle = OsRng.gen_range(0..CK_OBJECT_HANDLE::MAX);
        while self.objects.contains_key(&object_handle) {
            object_handle = OsRng.gen_range(0..CK_OBJECT_HANDLE::MAX);
        }

        object_handle
    }

    pub(crate) fn get_token(&self) -> TokenStore {
        self.token.clone()
    }

    // TODO: return an error if search not innited
    pub fn get_filtered_handles(&mut self, object_count: usize) -> Vec<CK_OBJECT_HANDLE> {
        let Some( object_search) = self.object_search.as_ref() else {
            return vec![]; // TODO: return error
        };
        if self.object_search_iterator.is_none() {
            self.object_search_iterator = Some(
                self.objects
                    .iter()
                    .filter(|(_handle, object)| {
                        object.does_template_match(object_search.get_template())
                    })
                    .map(|(&handle, _)| handle)
                    .collect::<Vec<CK_OBJECT_HANDLE>>() // TODO: refactor, ineffective
                    .into_iter(),
            );
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
        let pubkey_object = PublicKeyObject::new(pubkey.clone());
        let pubkey_handle = self.create_object(CryptokiArc {
            value: Arc::new(RwLock::new(pubkey_object)),
        });
        let private_key = PrivateKeyObject::new(pubkey);
        let private_key_handle = self.create_object(CryptokiArc {
            value: Arc::new(RwLock::new(private_key)),
        });
        (private_key_handle, pubkey_handle)
    }
}
