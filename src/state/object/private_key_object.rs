use uuid::Uuid;

use crate::{
    cryptoki::bindings::{
        CKA_CLASS, CKA_ID, CKA_SIGN, CKA_VALUE, CKO_PRIVATE_KEY, CK_ATTRIBUTE_TYPE, CK_TRUE,
    },
    state::object::cryptoki_object::AttributeValidator,
};

use super::{
    cryptoki_object::{AttributeMatcher, AttributeValue, Attributes, ByteVector, CryptokiObject},
    template::Template,
};

#[derive(Clone)]
pub(crate) struct PrivateKeyObject {
    id: Uuid,
    attributes: Attributes,
}

impl PrivateKeyObject {
    pub(crate) fn new() -> Self {
        let mut attributes = Attributes::new();
        attributes.insert(CKA_ID as CK_ATTRIBUTE_TYPE, None);
        attributes.insert(
            CKA_SIGN as CK_ATTRIBUTE_TYPE,
            Some((CK_TRUE as u8).to_le_bytes().to_vec()),
        );
        let mut object = Self {
            id: Uuid::new_v4(),
            attributes,
        };
        object.set_attribute(
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            (CKO_PRIVATE_KEY as CK_ATTRIBUTE_TYPE)
                .to_le_bytes()
                .to_vec(),
        );
        object
    }
}
impl CryptokiObject for PrivateKeyObject {
    fn from_parts(id: Uuid, attributes: Attributes) -> Self
    where
        Self: Sized,
    {
        assert!(attributes.validate_template_class(
            &(CKO_PRIVATE_KEY as CK_ATTRIBUTE_TYPE)
                .to_le_bytes()
                .to_vec()
        ));

        Self { id, attributes }
    }
    fn set_attribute(
        &mut self,
        attribute_type: CK_ATTRIBUTE_TYPE,
        value: Vec<u8>,
    ) -> Option<ByteVector> {
        self.attributes
            .insert(attribute_type, Some(value))
            .and_then(|x| x)
    }
    fn does_template_match(&self, template: &Template) -> bool {
        self.attributes.do_attributes_match(template)
    }
    fn store_value(&mut self, value: AttributeValue) -> Option<AttributeValue> {
        self.attributes
            .insert(CKA_VALUE as CK_ATTRIBUTE_TYPE, Some(value))
            .and_then(|x| x)
    }

    fn get_value(&self) -> Option<AttributeValue> {
        self.get_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE)
    }
    fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        let attributes = template.into_attributes();
        assert!(attributes.validate_template_class(
            &(CKO_PRIVATE_KEY as CK_ATTRIBUTE_TYPE)
                .to_le_bytes()
                .to_vec()
        ));
        Self {
            id: Uuid::new_v4(),
            attributes,
        }
    }

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        self.attributes.get(&attribute_type).and_then(|x| x.clone())
    }

    fn get_id(&self) -> &Uuid {
        &self.id
    }
    fn into_attributes(self) -> Attributes {
        self.attributes
    }
    fn get_attributes(&self) -> &Attributes {
        &self.attributes
    }
}
