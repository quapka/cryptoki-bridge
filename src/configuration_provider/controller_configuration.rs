use core::fmt;
use std::env;

use crate::communicator::task_name_provider::get_binary_name;

use super::{
    configuration_provider_error::ConfigurationProviderError,
    interface_configuration::InterfaceConfiguration,
    interface_configuration_response::InterfaceConfigurationResponse, ConfigurationProvider,
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
        let tool_parameter = self
            .tool_name
            .as_ref()
            .map(map_auxiliary_tools)
            .map(|tool_name| format!("tool={}", tool_name))
            .unwrap_or_default();
        let configuration: InterfaceConfigurationResponse = reqwest::blocking::get(format!(
            "http://www.localhost:{CONTROLLER_PORT}/{effective_interface_type}/configuration?{tool_parameter}"
        ))?
        .json()?;
        Ok(configuration.into())
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

/// Maps names of auxiliary tools to the actual tool names, e.g.,
/// `ssh-keygen` will be mapped to `ssh`, otherwise the user would
/// have to configure multiple configurations for auxiliary tools.
/// TODO: this needs some brainstorming and potentially feedback from the users
///
/// # Arguments
///
/// * `tool_name` - The name of the tool to map.
fn map_auxiliary_tools(tool_name: &String) -> String {
    match tool_name.as_str() {
        "ssh-keygen" => "ssh".to_string(),
        _ => tool_name.into(),
    }
}
