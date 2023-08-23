use crate::communicator::GroupId;

use self::configuration_provider_error::ConfigurationProviderError;

mod configuration_provider_error;
mod env_configuration;

pub(crate) trait ConfigurationProvider {
    fn get_communicator_url(&self) -> Result<Option<String>, ConfigurationProviderError>;

    fn get_group_id(&self) -> Result<Option<GroupId>, ConfigurationProviderError>;

    fn get_communicator_certificate_path(
        &self,
    ) -> Result<Option<String>, ConfigurationProviderError>;
}
