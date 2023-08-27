use crate::communicator::GroupId;

use self::configuration_provider_error::ConfigurationProviderError;

mod configuration_provider_error;
pub(crate) mod controller_configuration;
pub(crate) mod env_configuration;
pub(crate) mod root_configuration;

pub(crate) trait ConfigurationProvider: Send + Sync {
    fn get_communicator_url(&self) -> Result<Option<String>, ConfigurationProviderError>;

    fn get_group_id(&self) -> Result<Option<GroupId>, ConfigurationProviderError>;

    fn get_communicator_certificate_path(
        &self,
    ) -> Result<Option<String>, ConfigurationProviderError>;
}
