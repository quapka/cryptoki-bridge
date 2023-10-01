use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rusqlite::{named_params, Connection};
use uuid::Uuid;

use crate::{
    cryptoki::bindings::{
        CKA_CLASS, CKA_LABEL, CKO_DATA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
        CK_ATTRIBUTE_TYPE,
    },
    state::object::{
        cryptoki_object::{AttributeValue, CryptokiObject},
        object_class::ObjectClass,
        object_search::ObjectSearch,
    },
};

use super::{
    cryptoki_repo::CryptokiRepo, models::ObjectModel, persistence_error::PersistenceError,
};

pub(crate) struct SqliteCryptokiRepo {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteCryptokiRepo {
    pub fn new(cryptoki_directory: PathBuf) -> Self {
        static CRYPTOKI_BRIDGE_DB_FILE: &str = "cryptoki-bridge.db";
        let cryptoki_sqlite_db = cryptoki_directory.join(CRYPTOKI_BRIDGE_DB_FILE);
        let cryptoki_sqlite_db = cryptoki_sqlite_db.to_str().unwrap();
        let connection = Arc::new(Mutex::new(Connection::open(cryptoki_sqlite_db).unwrap()));
        Self { connection }
    }

    pub(crate) fn create_tables(&self) -> Result<(), PersistenceError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS objects (
                `id` BLOB PRIMARY KEY,
                `class` INTEGER NOT NULL CHECK (class IN (1, 2, 3, 4)),
                `label` BLOB,
                `serialized_attributes` BLOB NOT NULL
            );",
                (),
            )
            .unwrap();
        Ok(())
    }

    fn filter_objects_in_db(
        &self,
        label: Option<AttributeValue>,
        class: Option<ObjectClass>,
    ) -> Result<Vec<Arc<dyn CryptokiObject>>, PersistenceError> {
        let connection = &self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT id, class, label, serialized_attributes FROM objects WHERE (:label IS NULL OR label = :label) AND (:class IS NULL or class = :class)")
            .unwrap();
        let rows = statement.query_map(
            named_params! {":label":label, ":class":class.map(|x| x as i32)},
            |row| -> Result<Arc<dyn CryptokiObject>, rusqlite::Error> {
                let object_model = ObjectModel::from_row(row)?;
                Ok(object_model.into())
            },
        )?;
        rows.into_iter()
            .map(|x| x.map_err(|err| PersistenceError::from(err)))
            .collect()
    }
}

impl CryptokiRepo for SqliteCryptokiRepo {
    fn store_object(&self, object: Arc<dyn CryptokiObject>) -> Result<Uuid, PersistenceError> {
        let connection = &self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "INSERT INTO objects (id, class, label, serialized_attributes) VALUES (?1, ?2, ?3, ?4)",
        ).unwrap();
        let object_model = ObjectModel::from(object);

        statement
            .execute((
                object_model.id.as_bytes(),
                object_model.class as i32,
                object_model.label,
                object_model.serialized_attributes,
            ))
            .unwrap();
        Ok(object_model.id)
    }

    fn destroy_object(
        &self,
        object_id: Uuid,
    ) -> Result<Option<Arc<dyn CryptokiObject>>, PersistenceError> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "DELETE FROM objects WHERE id = ?1 RETURNING id, class, label, serialized_attributes;",
        ).unwrap();

        let object_model = statement
            .query_row((object_id.as_bytes(),), |row| ObjectModel::from_row(row))
            .unwrap();

        Ok(Some(object_model.into()))
    }
    fn get_object(
        &self,
        object_id: Uuid,
    ) -> Result<Option<Arc<dyn CryptokiObject>>, PersistenceError> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT * FROM objects WHERE id = ?1;")
            .unwrap();

        let object_model = statement
            .query_row((object_id.as_bytes(),), |row| ObjectModel::from_row(row))
            .unwrap();

        Ok(Some(object_model.into()))
    }

    fn get_objects(
        &self,
        object_search: &ObjectSearch,
    ) -> Result<Vec<Arc<dyn CryptokiObject>>, PersistenceError> {
        let filter_label = object_search
            .get_template()
            .get_attributes()
            .get(&(CKA_LABEL as CK_ATTRIBUTE_TYPE))
            .and_then(|x| x.clone());
        let filter_class = object_search.get_template().get_class();
        let objects = self.filter_objects_in_db(filter_label, filter_class)?;
        Ok(objects
            .into_iter()
            .filter(|object| object.does_template_match(object_search.get_template()))
            .collect())
    }

    // TODO: consider get_object_ids
}

fn to_fixed_size_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into().unwrap_or_else(|vector: Vec<T>| {
        panic!(
            "Invalid vector length: expected {}, but got {}",
            N,
            vector.len()
        )
    })
}
impl From<&Arc<dyn CryptokiObject>> for ObjectClass {
    fn from(value: &Arc<dyn CryptokiObject>) -> Self {
        let class = CK_ATTRIBUTE_TYPE::from_le_bytes(to_fixed_size_array(
            value.get_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE).unwrap(),
        ));
        match class as u32 {
            CKO_PRIVATE_KEY => ObjectClass::PrivateKey,
            CKO_PUBLIC_KEY => ObjectClass::PublicKey,
            CKO_SECRET_KEY => ObjectClass::SecretKey,
            CKO_DATA => ObjectClass::Data,
            _ => panic!("Invalid object class"),
        }
    }
}

pub(crate) fn from_i32(value: i32) -> Option<ObjectClass> {
    match value {
        1 => Some(ObjectClass::Data),
        2 => Some(ObjectClass::SecretKey),
        3 => Some(ObjectClass::PrivateKey),
        4 => Some(ObjectClass::PublicKey),
        _ => None,
    }
}
