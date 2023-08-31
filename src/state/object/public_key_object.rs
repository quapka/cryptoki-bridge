use crate::cryptoki::bindings::{
    CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKK_ECDSA, CK_ATTRIBUTE_TYPE,
};

use super::{cryptoki_object::CryptokiObject, object_class::ObjectClass, template::Template};

const DER_OCTET_STRING_TAG: u8 = 0x04;
const NIST_P256_EC_PARAMS_DER_HEX: &str = "06082a8648ce3d030107";
pub(crate) struct PublicKeyObject {
    data: Vec<u8>,
}

impl PublicKeyObject {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    fn format_public_key(&self) -> Vec<u8> {
        let mut public_key = self.data.clone();
        let data_len = public_key.len();
        public_key.insert(0, DER_OCTET_STRING_TAG);
        public_key.insert(1, data_len as u8);
        public_key
    }
}
impl CryptokiObject for PublicKeyObject {
    fn does_template_match(&self, template: &Template) -> bool {
        if let Some(class) = template.get_class() {
            class == ObjectClass::PublicKey
        } else {
            false
        }
    }

    fn store_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }
    fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        // TODO

        Self { data: vec![] }
    }

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        // todo implement
        if attribute_type == CKA_KEY_TYPE as u64 {
            return Some(CKK_ECDSA.to_le_bytes().into());
        }
        if attribute_type == CKA_LABEL as u64 {
            return Some("meesign".as_bytes().into());
        }

        if attribute_type == CKA_ID as u64 {
            return Some("".as_bytes().into());
        }

        if attribute_type == CKA_EC_PARAMS as u64 {
            return Some(hex::decode(NIST_P256_EC_PARAMS_DER_HEX).unwrap());
        }

        if attribute_type != CKA_EC_POINT as u64 {
            return None;
        }

        Some(self.format_public_key())
    }

    fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }
}
