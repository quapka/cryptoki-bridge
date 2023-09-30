use std::sync::Arc;

use rusqlite::Row;
use uuid::Uuid;

use crate::cryptoki::bindings::{CKA_LABEL, CK_ATTRIBUTE_TYPE};
use crate::state::object::{cryptoki_object::CryptokiObject, object_class::ObjectClass};

use super::sqlite_cryptoki_repo::from_i32;
pub(crate) struct ObjectModel {
    pub id: Uuid,
    pub class: ObjectClass,
    pub label: Option<Vec<u8>>,
    pub serialized_attributes: Vec<u8>,
}

impl ObjectModel {
    pub(crate) fn from_row(row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let uuid: [u8; 16] = row.get(0)?;
        Ok(ObjectModel {
            id: Uuid::from_bytes(uuid),
            class: from_i32(row.get(1)?).unwrap(),
            label: row.get(2)?,
            serialized_attributes: row.get(3)?,
        })
    }
}

impl From<Arc<dyn CryptokiObject>> for ObjectModel {
    fn from(value: Arc<dyn CryptokiObject>) -> Self {
        let class = ObjectClass::from(&value);
        let label = value.get_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE);
        let id = *value.get_id();
        let attributes = bincode::serialize(&value.get_attributes().clone()).unwrap();
        Self {
            id,
            class,
            label,
            serialized_attributes: attributes,
        }
    }
}
