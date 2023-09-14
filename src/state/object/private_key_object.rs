use crate::cryptoki::bindings::{CKA_ALWAYS_AUTHENTICATE, CK_ATTRIBUTE_TYPE, CK_FALSE};

use super::{cryptoki_object::CryptokiObject, object_class::ObjectClass, template::Template};

pub(crate) struct PrivateKeyObject {
    group_id: Vec<u8>,
}

impl PrivateKeyObject {
    pub(crate) fn new(group_id: Vec<u8>) -> Self {
        Self { group_id }
    }
}
impl CryptokiObject for PrivateKeyObject {
    fn does_template_match(&self, template: &Template) -> bool {
        if let Some(class) = template.get_class() {
            class == ObjectClass::PrivateKey
        } else {
            false
        }
    }

    fn store_data(&mut self, data: Vec<u8>) {
        self.group_id = data;
    }
    fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        // TODO

        Self { group_id: vec![] }
    }

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        if attribute_type == CKA_ALWAYS_AUTHENTICATE as CK_ATTRIBUTE_TYPE {
            return Some(CK_FALSE.to_le_bytes().into());
        }
        None
    }

    fn get_data(&self) -> Vec<u8> {
        self.group_id.clone()
    }
}
