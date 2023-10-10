use std::{ptr, sync::Arc};

use rand::{rngs::OsRng, Rng};

use super::{
    bindings::{
        CKM_AES_KEY_GEN, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID, CKR_OK,
        CKR_SESSION_HANDLE_INVALID, CK_ATTRIBUTE_PTR, CK_BYTE_PTR, CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
    },
    internals::encryption::{decrypt, destructure_iv_ciphertext, encrypt},
    utils::FromPointer,
};
use crate::{
    state::object::{
        cryptoki_object::CryptokiObject, private_key_object::PrivateKeyObject,
        secret_key_object::SecretKeyObject, template::Template,
    },
    STATE,
};

pub(crate) type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
pub(crate) type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
pub(crate) const AES_BLOCK_SIZE: usize = 16;
pub(crate) const AES_IV_SIZE: usize = AES_BLOCK_SIZE;

/// Generates a secret key or set of domain parameters, creating a new object
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the generation mechanism
/// * `pTemplate` - points to the template for the new key or set of domain parameters
/// * `ulCount` - the number of attributes in the template
/// * `phKey` - points to the location that receives the handle of the new key or set of domain parameters
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if pMechanism.is_null() || pTemplate.is_null() || phKey.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let Ok(mut state) = STATE.write() else {
        return CKR_GENERAL_ERROR as CK_RV;
    };
    let Some(state) = state.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
    };

    let mechanism = unsafe { *pMechanism };
    // todo: implement others
    if mechanism.mechanism as u32 != CKM_AES_KEY_GEN {
        return CKR_FUNCTION_NOT_SUPPORTED as CK_RV;
    }
    let template = unsafe { Vec::from_pointer(pTemplate, ulCount as usize) };
    let template = Template::from(template);
    let mut object = SecretKeyObject::from_template(template);

    let key: [u8; 16] = OsRng.gen();
    object.store_value(key.into());

    let return_code = match state.get_session_mut(&hSession) {
        Some(mut session) => {
            let handle = session.create_object(Arc::new(object));
            unsafe { *phKey = handle };
            CKR_OK as CK_RV
        }
        None => CKR_SESSION_HANDLE_INVALID as CK_RV,
    };

    return_code
}

/// Generates a public/private key pair, creating new key objects
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the key generation mechanism
/// * `pPublicKeyTemplate` - points to the template for the public key
/// * `ulPublicKeyAttributeCount` - the number of attributes in the public-key template
/// * `pPrivateKeyTemplate` - points to the template for the private key
/// * `ulPrivateKeyAttributeCount` - the number of attributes in the private-key template
/// * `phPublicKey` - points to the location that receives the handle of the new public key
/// * `phPrivateKey` - points to the location that receives the handle of the new private key
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let Ok(state) = STATE.read() else {
        return CKR_GENERAL_ERROR as CK_RV;
    };
    let Some(state) = state.as_ref() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
    };

    let Some(session) = state.get_session(&hSession) else {
        return CKR_SESSION_HANDLE_INVALID as CK_RV;
    };
    let (private_key_handle, pubkey_handle) = session.get_keypair();

    unsafe { *phPublicKey = pubkey_handle };

    unsafe { *phPrivateKey = private_key_handle };

    CKR_OK as CK_RV
}

/// Wraps (i.e., encrypts) a private or secret key
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the wrapping mechanism
/// * `hWrappingKey` - the handle of the wrapping key
/// * `hKey` - the handle of the key to be wrapped
/// * `pWrappedKey` - points to the location that receives the wrapped key
/// * `pulWrappedKeyLen` - points to the location that receives the length of the wrapped key
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulWrappedKeyLen.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let Ok(state) = STATE.read() else {
        return CKR_GENERAL_ERROR as CK_RV;
    };
    let Some(state) = state.as_ref() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
    };

    let Some(session) = state.get_session(&hSession) else {
        return CKR_SESSION_HANDLE_INVALID as CK_RV;
    };
    let Some(wrapping_key) = session.get_object(hWrappingKey) else {
        return CKR_KEY_HANDLE_INVALID as CK_RV;
    };
    let Some(private_key) = session.get_object(hKey) else {
        return CKR_KEY_HANDLE_INVALID as CK_RV;
    };
    let private_key = private_key.get_value().unwrap();
    let key = &wrapping_key.get_value().unwrap();

    let encryption_output = encrypt(key, private_key);
    let ciphertext_with_iv = encryption_output.into_combined();
    unsafe {
        *pulWrappedKeyLen = ciphertext_with_iv.len() as CK_ULONG;
    }

    if pWrappedKey.is_null() {
        return CKR_OK as CK_RV;
    }

    unsafe {
        ptr::copy(
            ciphertext_with_iv.as_ptr(),
            pWrappedKey,
            ciphertext_with_iv.len(),
        );
    }

    // TODO: either buffer ciphertext length or only precompute it if pWrappedKey is null
    // now encryption is done twice
    CKR_OK as CK_RV
}

/// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the unwrapping mechanism
/// * `hUnwrappingKey` - the handle of the unwrapping key
/// * `pWrappedKey` - points to the wrapped key
/// * `ulWrappedKeyLen` - the length of the wrapped key
/// * `pTemplate` - points to the template for the new key
/// * `ulAttributeCount` - the number of attributes in the template
/// * `phKey` - points to the location that receives the handle of the recovered key
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if pWrappedKey.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let Ok(mut state) = STATE.write() else {
        return CKR_GENERAL_ERROR as CK_RV;
    };
    let Some(state) = state.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
    };

    let Some(mut session) = state.get_session_mut(&hSession) else {
        return CKR_SESSION_HANDLE_INVALID as CK_RV;
    };
    let Some(unwrapping_key) = session.get_object(hUnwrappingKey) else {
        return CKR_KEY_HANDLE_INVALID as CK_RV;
    };

    let key = unwrapping_key.get_value().unwrap();
    let encryption_output =
        unsafe { destructure_iv_ciphertext(pWrappedKey, ulWrappedKeyLen as usize) };

    let plaintext = decrypt(&key, encryption_output.ciphertext, encryption_output.iv);

    // TODO: create from template
    let mut private_key_object = PrivateKeyObject::new();
    private_key_object.store_value(plaintext);
    let handle = session.create_ephemeral_object(Arc::new(private_key_object));
    unsafe {
        *phKey = handle;
    }
    CKR_OK as CK_RV
}
