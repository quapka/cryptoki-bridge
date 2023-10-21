use core::fmt;
use std::env;

use serde::Deserialize;

use crate::communicator::GroupId;

use super::{configuration_provider_error::ConfigurationProviderError, ConfigurationProvider};

static CONTROLLER_PORT: &str = "11115";
static IS_INTERFACE_USED_FOR_FIDO_ENV_NAME: &str = "USED_AS_FIDO";

pub(crate) struct ControllerConfiguration {}

#[derive(Deserialize)]
pub(crate) struct InterfaceConfiguration {
    communicator_url: String,
    group_id: GroupId,
}

impl ControllerConfiguration {
    pub(crate) fn new() -> Self {
        Self {}
    }

    fn fetch_data(&self) -> Result<InterfaceConfiguration, ConfigurationProviderError> {
        let effective_interface_type = EffectiveInterfaceType::from_environment();
        let effective_interface_type = effective_interface_type.to_interface_string();

        let configuration: InterfaceConfiguration = reqwest::blocking::get(format!(
            "http://www.localhost:{CONTROLLER_PORT}/{effective_interface_type}/configuration"
        ))?
        .json()?;
        Ok(configuration)
    }
}

// TODO: cache fetch_data calls + timestamps?
impl ConfigurationProvider for ControllerConfiguration {
    fn get_communicator_url(&self) -> Result<Option<String>, ConfigurationProviderError> {
        let configuration = self.fetch_data()?;
        Ok(Some(configuration.communicator_url))
    }

    fn get_group_id(&self) -> Result<Option<GroupId>, ConfigurationProviderError> {
        let configuration = self.fetch_data()?;
        Ok(Some(configuration.group_id))
    }

    fn get_communicator_certificate_path(
        &self,
    ) -> Result<Option<String>, ConfigurationProviderError> {
        let configuration = self.fetch_data()?;
        let url = configuration.communicator_url;
        let response: CertificateResponse = reqwest::blocking::get(format!(
            "http://www.localhost:{CONTROLLER_PORT}/{url}/certificate_path"
        ))?
        .json()?;

        Ok(response.certificate_path)
    }
}

#[derive(Deserialize)]
struct CertificateResponse {
    certificate_path: Option<String>,
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
