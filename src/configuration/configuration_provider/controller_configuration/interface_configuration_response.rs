use serde::Deserialize;

use crate::communicator::GroupId;

/// Used to deserialize the response from the controller server
#[derive(Deserialize, Clone)]
pub(crate) struct InterfaceConfigurationResponse {
    communicator_hostname: String,
    communicator_port: u16,
    communicator_certificate_path: String,
    group_id: GroupId,
}

impl InterfaceConfigurationResponse {
    pub fn get_communicator_hostname(&self) -> &str {
        &self.communicator_hostname
    }

    pub fn get_communicator_port(&self) -> u16 {
        self.communicator_port
    }

    pub fn get_group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn get_communicator_certificate_path(&self) -> &str {
        &self.communicator_certificate_path
    }
}
