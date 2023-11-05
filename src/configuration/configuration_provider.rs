pub(crate) mod configuration_provider_error;
pub(crate) mod controller_configuration;
pub(crate) mod env_configuration;

use self::configuration_provider_error::ConfigurationProviderError;

use super::interface_configuration::InterfaceConfiguration;

/// Provides the configuration for this interface
pub(crate) trait ConfigurationProvider: Send + Sync {
    /// Returns the configuration for this interface
    fn get_interface_configuration(
        &self,
    ) -> Result<InterfaceConfiguration, ConfigurationProviderError>;
}
