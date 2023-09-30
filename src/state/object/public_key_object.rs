use uuid::Uuid;

use crate::{
    cryptoki::bindings::{
        CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_VALUE,
        CKK_ECDSA, CKO_PUBLIC_KEY, CK_ATTRIBUTE_TYPE,
    },
    state::object::cryptoki_object::AttributeValidator,
};

use super::{
    cryptoki_object::{AttributeMatcher, AttributeValue, Attributes, CryptokiObject},
    template::Template,
};

const DER_OCTET_STRING_TAG: u8 = 0x04;
const NIST_P256_EC_PARAMS_DER_HEX: &str = "06082a8648ce3d030107";

#[derive(Clone)]
pub(crate) struct PublicKeyObject {
    id: Uuid,
    attributes: Attributes,
}

impl PublicKeyObject {
    pub(crate) fn new() -> Self {
        let mut object = Self {
            id: Uuid::new_v4(),
            attributes: Attributes::new(),
        };
        // TODO: check endianity
        object.set_attribute(
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            (CKO_PUBLIC_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec(),
        );
        object
    }

    fn format_public_key(&self) -> Vec<u8> {
        let mut public_key = self.get_value().unwrap();
        let data_len = public_key.len();
        public_key.insert(0, DER_OCTET_STRING_TAG);
        public_key.insert(1, data_len as u8);
        public_key
    }
}
impl CryptokiObject for PublicKeyObject {
    fn from_parts(id: Uuid, attributes: Attributes) -> Self
    where
        Self: Sized,
    {
        assert!(attributes.validate_template_class(
            &(CKO_PUBLIC_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
        ));

        Self { id, attributes }
    }
    fn set_attribute(
        &mut self,
        attribute_type: CK_ATTRIBUTE_TYPE,
        value: AttributeValue,
    ) -> Option<AttributeValue> {
        self.attributes
            .insert(attribute_type, Some(value))
            .and_then(|x| x)
    }
    fn store_value(&mut self, value: AttributeValue) -> Option<AttributeValue> {
        self.attributes
            .insert(CKA_VALUE as CK_ATTRIBUTE_TYPE, Some(value))
            .and_then(|x| x)
    }

    fn get_value(&self) -> Option<AttributeValue> {
        self.get_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE)
    }
    fn does_template_match(&self, template: &Template) -> bool {
        self.attributes.do_attributes_match(template)
    }

    fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        let attributes = template.into_attributes();
        assert!(attributes.validate_template_class(
            &(CKO_PUBLIC_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
        ));

        Self {
            id: Uuid::new_v4(),
            attributes,
        }
    }

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        // TODO: remove default values
        if attribute_type == CKA_KEY_TYPE as CK_ATTRIBUTE_TYPE {
            return Some(CKK_ECDSA.to_le_bytes().into());
        }
        if attribute_type == CKA_LABEL as CK_ATTRIBUTE_TYPE {
            return Some("meesign".as_bytes().into());
        }

        if attribute_type == CKA_ID as CK_ATTRIBUTE_TYPE {
            return Some("".as_bytes().into());
        }

        if attribute_type == CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE {
            return Some(hex::decode(NIST_P256_EC_PARAMS_DER_HEX).unwrap());
        }

        if attribute_type == CKA_EC_POINT as CK_ATTRIBUTE_TYPE {
            return Some(self.format_public_key());
        }
        self.attributes.get(&attribute_type).and_then(|x| x.clone())
    }

    fn get_id(&self) -> &uuid::Uuid {
        &self.id
    }

    fn into_attributes(self) -> Attributes {
        self.attributes
    }
    fn get_attributes(&self) -> &Attributes {
        &self.attributes
    }
}
