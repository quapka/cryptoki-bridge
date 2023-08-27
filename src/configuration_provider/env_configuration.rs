use std::env;

use crate::communicator::GroupId;

use super::{configuration_provider_error::ConfigurationProviderError, ConfigurationProvider};

static COMMUNICATOR_URL_ENV_NAME: &str = "COMMUNICATOR_URL";
static GROUP_ID_ENV_NAME: &str = "GROUP_ID";
static COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME: &str = "COMMUNICATOR_CERTIFICATE_PATH";

pub(crate) struct EnvConfiguration {}

impl EnvConfiguration {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl ConfigurationProvider for EnvConfiguration {
    fn get_communicator_url(&self) -> Result<Option<String>, ConfigurationProviderError> {
        Ok(Some(env::var(COMMUNICATOR_URL_ENV_NAME)?))
    }

    fn get_group_id(&self) -> Result<Option<GroupId>, ConfigurationProviderError> {
        let group_id_string = env::var(GROUP_ID_ENV_NAME)?;
        let group_id: GroupId = hex::decode(group_id_string)?;
        Ok(Some(group_id))
    }
    fn get_communicator_certificate_path(
        &self,
    ) -> Result<Option<String>, ConfigurationProviderError> {
        Ok(Some(env::var(COMMUNICATOR_CERTIFICATE_PATH_ENV_NAME)?))
    }
}
