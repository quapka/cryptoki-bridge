use crate::{
    cryptoki::bindings::CK_ATTRIBUTE_TYPE, state::object::cryptoki_object::AttributeValue,
};

const DER_OCTET_STRING_TYPE: u8 = 0x04;

pub(crate) fn as_der_octet_string(public_key: &[u8]) -> Vec<u8> {
    let data_len = public_key.len() as u8;
    let vector_len = (1 + 1 + data_len) as usize;
    let mut octet_string = Vec::with_capacity(vector_len);
    octet_string.push(DER_OCTET_STRING_TYPE);
    octet_string.push(data_len);
    octet_string.extend(public_key);
    octet_string
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

// TODO: don't panic
pub(crate) fn to_fixed_size_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into().unwrap_or_else(|vector: Vec<T>| {
        panic!(
            "Invalid vector length: expected {}, but got {}",
            N,
            vector.len()
        )
    })
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn given_public_key_as_der_octet_string_produces_valid_octet_string() {
        static PUBKEY_LENGTH: usize = 64;
        static EXPECTED_OCTET_STRING_LENGTH: usize = 1 + 1 + PUBKEY_LENGTH;
        let pubkey = vec![0xab; PUBKEY_LENGTH];
        let octet_string = as_der_octet_string(&pubkey);
        assert_eq!(octet_string.len(), EXPECTED_OCTET_STRING_LENGTH);
        assert_eq!(octet_string[0], 0x04);
        assert_eq!(octet_string[1], PUBKEY_LENGTH as u8);
    }
}
