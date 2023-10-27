use std::env::{self, VarError};

use crate::communicator::GroupId;

use super::{
    configuration_provider_error::ConfigurationProviderError,
    controller_configuration::EffectiveInterfaceType,
    interface_configuration::InterfaceConfiguration, ConfigurationProvider,
};

static COMMUNICATOR_URL_ENV_NAME: &str = "COMMUNICATOR_URL";
static GROUP_ID_ENV_NAME: &str = "GROUP_ID";
static COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME: &str = "COMMUNICATOR_CERTIFICATE_PATH";

pub(crate) struct EnvConfiguration {
    configuration: InterfaceConfiguration,
}

impl EnvConfiguration {
    fn get_communicator_url() -> Result<String, VarError> {
        env::var(COMMUNICATOR_URL_ENV_NAME)
    }

    fn get_group_id() -> Result<GroupId, ConfigurationProviderError> {
        let group_id_string = env::var(GROUP_ID_ENV_NAME)?;
        let group_id: GroupId = hex::decode(group_id_string)?;
        Ok(group_id)
    }

    fn get_communicator_certificate_path() -> Result<String, VarError> {
        env::var(COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME)
    }

    pub(crate) fn new() -> Result<Option<Self>, ConfigurationProviderError> {
        let url = Self::get_communicator_url();
        let cert_path = Self::get_communicator_certificate_path();
        let group_id = Self::get_group_id();

        let configuration = match (url, cert_path, group_id) {
            (Ok(url), Ok(cert_path), Ok(group_id)) => {
                InterfaceConfiguration::new(url, group_id, cert_path)
            }
            (
                Err(VarError::NotPresent),
                Err(VarError::NotPresent),
                Err(ConfigurationProviderError::ValueNotSet(VarError::NotPresent)),
            ) => return Ok(None),
            (url, id, path) => {
                url?;
                id?;
                path?;
                unreachable!()
            }
        };
        Ok(Some(Self { configuration }))
    }
}

impl ConfigurationProvider for EnvConfiguration {
    fn get_interface_configuration(
        &self,
    ) -> Result<InterfaceConfiguration, ConfigurationProviderError> {
        Ok(self.configuration.clone())
    }
}
