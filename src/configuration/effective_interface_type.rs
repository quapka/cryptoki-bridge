use std::{env, fmt};

static IS_INTERFACE_USED_FOR_FIDO_ENV_NAME: &str = "USED_AS_FIDO";

/// Represents the actuall effective interface type.
/// This library can be used by other high-lvl interfaces,
/// e.g., FIDO emulators
#[derive(Eq, PartialEq)]
pub(crate) enum EffectiveInterfaceType {
    WebAuthn,
    Cryptoki,
}

impl EffectiveInterfaceType {
    pub(crate) fn from_environment() -> Self {
        let is_interface_used_for_fido = env::var(IS_INTERFACE_USED_FOR_FIDO_ENV_NAME).is_ok();
        if is_interface_used_for_fido {
            Self::WebAuthn
        } else {
            Self::Cryptoki
        }
    }

    pub(crate) fn to_interface_string(&self) -> &str {
        match self {
            Self::WebAuthn => "webauthn",
            Self::Cryptoki => "cryptoki",
        }
    }
}

impl fmt::Display for EffectiveInterfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebAuthn => write!(f, "WebAuthn"),
            Self::Cryptoki => write!(f, "Cryptoki"),
        }
    }
}
