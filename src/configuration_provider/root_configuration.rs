use crate::communicator::GroupId;

use super::{configuration_provider_error::ConfigurationProviderError, ConfigurationProvider};

pub(crate) struct RootConfiguration {
    providers: Vec<Box<dyn ConfigurationProvider>>,
}

impl RootConfiguration {
    pub fn new() -> Self {
        Self {
            providers: Default::default(),
        }
    }

    pub fn add_provider(mut self, provider: Box<dyn ConfigurationProvider>) -> Self {
        self.providers.push(provider);
        self
    }
}

impl ConfigurationProvider for RootConfiguration {
    fn get_communicator_url(&self) -> Result<Option<String>, ConfigurationProviderError> {
        Ok(self
            .providers
            .iter()
            .find_map(|provider| provider.get_communicator_url().unwrap_or_default()))
    }

    fn get_group_id(&self) -> Result<Option<GroupId>, ConfigurationProviderError> {
        Ok(self
            .providers
            .iter()
            .find_map(|provider| provider.get_group_id().unwrap_or_default()))
    }

    fn get_communicator_certificate_path(
        &self,
    ) -> Result<Option<String>, ConfigurationProviderError> {
        Ok(self.providers.iter().find_map(|provider| {
            provider
                .get_communicator_certificate_path()
                .unwrap_or_default()
        }))
    }
}
