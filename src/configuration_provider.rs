use self::{
    configuration_provider_error::ConfigurationProviderError,
    interface_configuration::InterfaceConfiguration,
};

pub(crate) mod configuration_provider_error;
pub(crate) mod controller_configuration;
pub(crate) mod env_configuration;
mod interface_configuration;
mod interface_configuration_response;

pub(crate) trait ConfigurationProvider: Send + Sync {
    fn get_interface_configuration(
        &self,
    ) -> Result<InterfaceConfiguration, ConfigurationProviderError>;
}
