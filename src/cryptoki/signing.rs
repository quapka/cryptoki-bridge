use std::ptr;

use crate::{
    state::{object::template::Template, session::session::Signer},
    STATE,
};
const CKA_REQUEST_ORIGINATOR: CK_ATTRIBUTE_TYPE =
    (CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE) | 0x000000000000abcd;

use super::{
    bindings::{
        CKA_VENDOR_DEFINED, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_NOT_INITIALIZED,
        CKR_SESSION_HANDLE_INVALID, CK_ATTRIBUTE_PTR, CK_ATTRIBUTE_TYPE, CK_BYTE_PTR,
        CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
    },
    utils::FromPointer,
};

/// Initializes a signature operation, where the signature is an appendix to the data
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the signature mechanism
/// * `hKey` - handle of the signature key
#[allow(non_snake_case)]
pub(super) fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    let Ok(mut state) = STATE.write() else {
        return CKR_GENERAL_ERROR as CK_RV;
    };
    let Some(state) = state.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
    };
    let Some(mut session) = state.get_session_mut(&hSession) else {
        return CKR_SESSION_HANDLE_INVALID as CK_RV;
    };
    let Some(signing_key) = session.get_object(hKey) else {
        return CKR_OBJECT_HANDLE_INVALID as CK_RV;
    };
    let mechanism = unsafe { *pMechanism };
    let attributes = unsafe {
        Vec::from_pointer(
            mechanism.pParameter as CK_ATTRIBUTE_PTR,
            mechanism.ulParameterLen as usize,
        )
    };
    let template = Template::from(attributes);
    let request_originator = template
        .get_value(&(CKA_REQUEST_ORIGINATOR as CK_ATTRIBUTE_TYPE))
        .map(|originator| String::from_utf8(originator).ok())
        .and_then(|x| x);

    session.set_signer(Signer::new(signing_key, request_originator));

    CKR_OK as CK_RV
}

/// Signs data in a single part, where the signature is an appendix to the data
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pData` - points to the data
/// * `ulDataLen` - the length of the data
/// * `pSignature` - points to the location that receives the signature
/// * `pulSignatureLen` - points to the location that holds the length of the signature
#[allow(non_snake_case)]
pub(super) fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    // TODO: refactor to avoid multiple mut references
    if pulSignatureLen.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let mut signer_ = None;
    {
        let Ok(state) = STATE.read() else {
            return CKR_GENERAL_ERROR as CK_RV;
        };
        let Some(state) = state.as_ref() else {
            return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
        };
        let Some(session) = state.get_session(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID as CK_RV;
        };
        let Some(signer) = session.get_signer() else {
            return CKR_OPERATION_NOT_INITIALIZED as CK_RV;
        };
        signer_ = Some(signer);
    }
    let mut signer = signer_.unwrap();
    if signer.response.is_none() {
        // response not stored from the previous call, send the request
        let pubkey = signer.key.get_value().unwrap();

        let auth_data = unsafe { Vec::from_pointer(pData, ulDataLen as usize) };

        let mut response_ = None;
        {
            let Ok(mut state) = STATE.write() else {
                return CKR_GENERAL_ERROR as CK_RV;
            };
            let Some(state) = state.as_mut() else {
                return CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV;
            };

            let Ok(Some(response)) = state.send_signing_request_wait_for_response(
                pubkey,
                auth_data,
                signer.auth_request_originator,
            ) else {
                return CKR_FUNCTION_FAILED as CK_RV;
            };
            response_ = Some(response);
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
        let response = response_.unwrap();
        session.store_signing_response(response.clone());
        signer.response = Some(response);
    }

    let Some(response) = signer.response.as_ref() else {
        panic!("Shouldn't happen");
    };
    unsafe {
        *pulSignatureLen = response.len() as CK_ULONG;
    }

    if !pSignature.is_null() {
        unsafe {
            ptr::copy(response.as_ptr(), pSignature, response.len());
        }
    }

    CKR_OK as CK_RV
}
