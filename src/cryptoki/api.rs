use super::bindings::{
    CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_FLAGS, CK_FUNCTION_LIST_PTR_PTR, CK_INFO_PTR,
    CK_MECHANISM_PTR, CK_NOTIFY, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE,
    CK_SESSION_HANDLE_PTR, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO_PTR, CK_TOKEN_INFO_PTR,
    CK_ULONG, CK_ULONG_PTR, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VOID_PTR,
};
mod implementation {
    pub(super) use super::super::{
        decryption::{C_Decrypt, C_DecryptInit},
        encryption::{C_Encrypt, C_EncryptFinal, C_EncryptInit, C_EncryptUpdate},
        general_purpose::{C_Finalize, C_GetFunctionList, C_GetInfo, C_Initialize},
        key_management::{C_GenerateKey, C_GenerateKeyPair, C_UnwrapKey, C_WrapKey},
        message_digesting::{C_Digest, C_DigestInit},
        object_management::{
            C_CreateObject, C_DestroyObject, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit,
            C_GetAttributeValue,
        },
        session_management::{C_CloseSession, C_Login, C_Logout, C_OpenSession},
        signing::{C_Sign, C_SignInit},
        slot_token::{C_GetSlotInfo, C_GetSlotList, C_GetTokenInfo},
    };
}

/// This macro takes a function name along with its parameters and generates
/// two proxy functions conditionally compiling only the one for the current platform,
/// invoking the implementation function with the same name defined
///  in the `implementation` module.
///
/// # Arguments
///
/// - a function name with its parameters
///
/// # Example
///
/// ```
/// cryptoki_function!(C_Initialize(pInitArgs: CK_VOID_PTR));
/// ```
///
/// evaluates to
///
/// ```
/// #[no_mangle]
/// #[allow(non_snake_case)]
/// #[cfg(target_os = "linux")]
/// pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
///     implementation::C_Initialize(pInitArgs)
/// }
/// #[no_mangle]
/// #[allow(non_snake_case)]
/// #[cfg(target_os = "windows")]
/// pub extern "stdcall" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
///     implementation::C_Initialize(pInitArgs)
/// }
/// ```
macro_rules! cryptoki_function{
    ($function_name:ident($($parameter_name:ident : $parameter_type:ty),*)) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        #[cfg(target_os = "linux")]
        pub extern "C" fn $function_name($($parameter_name: $parameter_type),*) -> CK_RV {
            implementation::$function_name($($parameter_name),*)
        }

        #[no_mangle]
        #[allow(non_snake_case)]
        #[cfg(target_os = "windows")]
        pub extern "stdcall" fn $function_name($($parameter_name: $parameter_type),*) -> CK_RV {
            implementation::$function_name($($parameter_name),*)
        }
    }
}

// General purpose
cryptoki_function!(C_Initialize(pInitArgs: CK_VOID_PTR));
cryptoki_function!(C_Finalize(pReserved: CK_VOID_PTR));
cryptoki_function!(C_GetInfo(pInfo: CK_INFO_PTR));
cryptoki_function!(C_GetFunctionList(
    ppFunctionList: CK_FUNCTION_LIST_PTR_PTR));

// Decryption
cryptoki_function!(C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE));
cryptoki_function!(C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR
));

// Encryption
cryptoki_function!(C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
));
cryptoki_function!(C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR
));
cryptoki_function!(C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
));
cryptoki_function!(C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR
));

// Key management
cryptoki_function!(C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR));
cryptoki_function!(C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR));
cryptoki_function!(C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR
));
cryptoki_function!(C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
));

// Message digesting
cryptoki_function!(C_DigestInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR));
cryptoki_function!(C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR
));

// Object management
cryptoki_function!(C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR
));
cryptoki_function!(C_DestroyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE));
cryptoki_function!(C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG
));
cryptoki_function!(C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG
));
cryptoki_function!(C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR
));
cryptoki_function!(C_FindObjectsFinal(
    hSession: CK_SESSION_HANDLE));

// Session management
cryptoki_function!(C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR
));
cryptoki_function!(C_CloseSession(
    hSession: CK_SESSION_HANDLE));
cryptoki_function!(C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG
));
cryptoki_function!(C_Logout(
    hSession: CK_SESSION_HANDLE));

// Signing
cryptoki_function!( C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
));
cryptoki_function!(C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR
));

// Slot & token
cryptoki_function!( C_GetSlotList(
    _tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR
));
cryptoki_function!(C_GetTokenInfo(
    slotID: CK_SLOT_ID,
    pInfo: CK_TOKEN_INFO_PTR));
cryptoki_function!(C_GetSlotInfo(
    slotID: CK_SLOT_ID,
    pInfo: CK_SLOT_INFO_PTR));
