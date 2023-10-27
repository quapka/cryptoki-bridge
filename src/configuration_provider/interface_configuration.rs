use serde::Deserialize;

use crate::communicator::GroupId;

#[derive(Deserialize, Clone)]
pub(crate) struct InterfaceConfiguration {
    communicator_url: String,
    communicator_certificate_path: String,
    group_id: GroupId,
}

impl InterfaceConfiguration {
    pub fn new(
        communicator_url: String,
        group_id: GroupId,
        communicator_certificate_path: String,
    ) -> Self {
        Self {
            communicator_url,
            group_id,
            communicator_certificate_path,
        }
    }

    pub fn get_communicator_url(&self) -> &str {
        &self.communicator_url
    }

    pub fn get_group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn get_communicator_certificate_path(&self) -> &str {
        &self.communicator_certificate_path
    }
}
