use serde::Deserialize;

use crate::communicator::GroupId;

#[derive(Deserialize, Clone)]
pub(crate) struct InterfaceConfiguration {
    communicator_hostname: String,
    communicator_certificate_path: String,
    group_id: GroupId,
}

impl InterfaceConfiguration {
    pub fn new(
        communicator_hostname: String,
        group_id: GroupId,
        communicator_certificate_path: String,
    ) -> Self {
        Self {
            communicator_hostname,
            group_id,
            communicator_certificate_path,
        }
    }

    pub fn get_communicator_hostname(&self) -> &str {
        &self.communicator_hostname
    }

    pub fn get_group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn get_communicator_certificate_path(&self) -> &str {
        &self.communicator_certificate_path
    }
}
