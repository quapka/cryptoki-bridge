use std::env::{self, VarError};

use crate::communicator::GroupId;

use super::{
    configuration_provider_error::ConfigurationProviderError,
    interface_configuration::InterfaceConfiguration, ConfigurationProvider,
};

static COMMUNICATOR_HOSTNAME_ENV_NAME: &str = "COMMUNICATOR_HOSTNAME";
static GROUP_ID_ENV_NAME: &str = "GROUP_ID";
static COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME: &str = "COMMUNICATOR_CERTIFICATE_PATH";

pub(crate) struct EnvConfiguration {
    configuration: InterfaceConfiguration,
}

impl EnvConfiguration {
    fn get_communicator_hostname() -> Result<String, VarError> {
        env::var(COMMUNICATOR_HOSTNAME_ENV_NAME)
    }

    fn get_group_id() -> Result<Option<GroupId>, ConfigurationProviderError> {
        let Ok(group_id_string) = env::var(GROUP_ID_ENV_NAME) else {
            return Ok(None);
        };
        let group_id: GroupId = hex::decode(group_id_string)?;
        Ok(Some(group_id))
    }

    fn get_communicator_certificate_path() -> Result<String, VarError> {
        env::var(COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME)
    }

    pub(crate) fn new() -> Result<Option<Self>, ConfigurationProviderError> {
        let hostname = Self::get_communicator_hostname();
        let cert_path = Self::get_communicator_certificate_path();
        let group_id = Self::get_group_id();

        let configuration = match (hostname, cert_path, group_id) {
            (Ok(hostname), Ok(cert_path), Ok(group_id)) => {
                InterfaceConfiguration::new(hostname, group_id, cert_path)
            }
            (Err(VarError::NotPresent), Err(VarError::NotPresent), Ok(None)) => return Ok(None),
            (hostname, id, path) => {
                hostname?;
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
