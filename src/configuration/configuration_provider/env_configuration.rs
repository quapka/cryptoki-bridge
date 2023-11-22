use std::env::{self, VarError};

use crate::{
    communicator::GroupId, configuration::interface_configuration::InterfaceConfiguration,
};

use super::{configuration_provider_error::ConfigurationProviderError, ConfigurationProvider};

static COMMUNICATOR_HOSTNAME_ENV_NAME: &str = "COMMUNICATOR_HOSTNAME";
static COMMUNICATOR_PORT_ENV_NAME: &str = "COMMUNICATOR_PORT";
static GROUP_ID_ENV_NAME: &str = "GROUP_ID";
static COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME: &str = "COMMUNICATOR_CERTIFICATE_PATH";

static MEESIGN_SERVER_DEFAULT_PORT: u16 = 1337;

/// Provides configuration from the environment variables
pub(crate) struct EnvConfiguration {
    /// Configuration acquired from the env variables
    configuration: InterfaceConfiguration,
}

impl EnvConfiguration {
    fn get_communicator_hostname() -> Result<String, VarError> {
        env::var(COMMUNICATOR_HOSTNAME_ENV_NAME)
    }

    fn get_communicator_port() -> Result<String, VarError> {
        env::var(COMMUNICATOR_PORT_ENV_NAME)
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
        let port = match Self::get_communicator_port() {
            Ok(value) => match value.parse::<u16>() {
                Ok(number) => number,
                Err(_) => MEESIGN_SERVER_DEFAULT_PORT,
            },
            Err(_) => MEESIGN_SERVER_DEFAULT_PORT,
        };
        let cert_path = Self::get_communicator_certificate_path();
        let group_id = Self::get_group_id();

        // either allow none of the options specified, then we return None, or make sure
        // that the hostname and cert_path are correctly specified
        let configuration = match (hostname, cert_path, group_id) {
            (Ok(hostname), Ok(cert_path), Ok(group_id)) => {
                InterfaceConfiguration::new(hostname, port, group_id, cert_path)
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
