use crate::{
    cryptoki::bindings::CK_ATTRIBUTE_TYPE, state::object::cryptoki_object::AttributeValue,
};

const DER_OCTET_STRING_TAG: u8 = 0x04;

pub(crate) fn format_public_key(mut public_key: Vec<u8>) -> Vec<u8> {
    let data_len = public_key.len();
    public_key.insert(0, DER_OCTET_STRING_TAG);
    public_key.insert(1, data_len as u8);
    public_key
}

pub trait ToAttributeValue {
    fn to_attribute_value(self) -> AttributeValue;
}

impl ToAttributeValue for AttributeValue {
    fn to_attribute_value(self) -> AttributeValue {
        self
    }
}

impl ToAttributeValue for u32 {
    fn to_attribute_value(self) -> AttributeValue {
        (self as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
    }
}

impl ToAttributeValue for &str {
    fn to_attribute_value(self) -> AttributeValue {
        self.as_bytes().to_vec()
    }
}
