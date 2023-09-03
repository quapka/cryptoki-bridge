use std::env;

use serde::Deserialize;

use crate::communicator::GroupId;

use super::{configuration_provider_error::ConfigurationProviderError, ConfigurationProvider};

static CONTROLLER_PORT: &str = "12345"; // TODO
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
        let is_interface_used_for_fido = env::var(IS_INTERFACE_USED_FOR_FIDO_ENV_NAME).is_ok();
        let interface = if is_interface_used_for_fido {
            "webauthn"
        } else {
            "cryptoki"
        };
        let configuration: InterfaceConfiguration = reqwest::blocking::get(format!(
            "http://www.localhost:{CONTROLLER_PORT}/{interface}/configuration"
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
