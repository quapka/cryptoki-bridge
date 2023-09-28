use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use sqlite::Connection;
use uuid::Uuid;

use crate::state::object::{cryptoki_object::CryptokiObject, object_search::ObjectSearch};

use super::{cryptoki_repo::CryptokiRepo, persistence_error::PersistenceError};

pub(crate) struct SqliteCryptokiRepo {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteCryptokiRepo {
    pub fn new(cryptoki_directory: PathBuf) -> Self {
        static CRYPTOKI_BRIDGE_DB_FILE: &str = "cryptoki-bridge.db";
        let cryptoki_sqlite_db = cryptoki_directory.join(CRYPTOKI_BRIDGE_DB_FILE);
        let cryptoki_sqlite_db = cryptoki_sqlite_db.to_str().unwrap();
        // TODO: use cryptoki_sqlite_db
        let connection = Arc::new(Mutex::new(sqlite::open(":memory:").unwrap()));
        Self { connection }
    }

    pub(crate) fn create_tables(&self) -> Result<(), PersistenceError> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            "CREATE TABLE IF NOT EXISTS objects (
                id INTEGER PRIMARY KEY,
                type INTEGER NOT NULL,
                data BLOB NOT NULL
            );",
        )?;
        Ok(())
    }
}

impl CryptokiRepo for SqliteCryptokiRepo {
    fn store_object(&self, object: Arc<dyn CryptokiObject>) -> Result<Uuid, PersistenceError> {
        todo!()
    }

    fn destroy_object(
        &self,
        object_id: Uuid,
    ) -> Result<Option<Arc<dyn CryptokiObject>>, PersistenceError> {
        todo!()
    }
    fn get_object(
        &self,
        object_id: Uuid,
    ) -> Result<Option<Arc<dyn CryptokiObject>>, PersistenceError> {
        todo!()
    }

    fn get_objects(
        &self,
        object_search: &ObjectSearch,
    ) -> Result<Vec<Arc<dyn CryptokiObject>>, PersistenceError> {
        todo!()
    }

    // TODO: consider get_object_ids
}
