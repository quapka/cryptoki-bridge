use core::fmt;
use std::env;

use crate::communicator::task_name_provider::get_binary_name;

use super::{
    configuration_provider_error::ConfigurationProviderError,
    interface_configuration::InterfaceConfiguration, ConfigurationProvider,
};

static CONTROLLER_PORT: &str = "11115";
static IS_INTERFACE_USED_FOR_FIDO_ENV_NAME: &str = "USED_AS_FIDO";

pub(crate) struct ControllerConfiguration {
    effective_interface_type: EffectiveInterfaceType,
    tool_name: Option<String>,
}

impl ControllerConfiguration {
    pub(crate) fn new() -> Self {
        let effective_interface_type = EffectiveInterfaceType::from_environment();
        let tool_name = get_binary_name().unwrap_or(None);
        Self {
            effective_interface_type,
            tool_name,
        }
    }
}

impl ConfigurationProvider for ControllerConfiguration {
    fn get_interface_configuration(
        &self,
    ) -> Result<InterfaceConfiguration, ConfigurationProviderError> {
        let effective_interface_type = self.effective_interface_type.to_interface_string();

        let configuration: InterfaceConfiguration = reqwest::blocking::get(format!(
            "http://www.localhost:{CONTROLLER_PORT}/{effective_interface_type}/configuration"
        ))?
        .json()?;
        Ok(configuration)
    }
}

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

    fn to_interface_string(&self) -> &str {
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
