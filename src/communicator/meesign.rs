mod proto {
    tonic::include_proto!("meesign");
}

use tokio::time;
use tonic::{
    async_trait,
    transport::{Certificate, Channel, ClientTlsConfig, Uri},
};

use std::{cmp, str::FromStr, time::Duration};

use crate::communicator::meesign::proto::{mpc_client::MpcClient, GroupsRequest, KeyType};
use crate::communicator::AuthResponse;

use self::proto::{task::TaskState, SignRequest, TaskRequest};
use super::{
    communicator_error::CommunicatorError, group::Group, task_name_provider::TaskNameProvider,
    Communicator, GroupId, RequestData, TaskId,
};

static MAX_ATTEMPT_COUNT: usize = 60 * 2; // ATTEMPT_SLEEP_SEC as usize;
static ATTEMPT_SLEEP_MILLIS: u64 = 50;
// static ATTEMPT_SLEEP_SEC: f64 = cmp::max(ATTEMPT_SLEEP_MILLIS as f64 / 1000.0, 1.0);

/// Communicates with the MeeSign server
pub(crate) struct Meesign {
    client: MpcClient<Channel>,
}

impl Meesign {
    pub async fn new(
        hostname: String,
        port: u16,
        certificate: Certificate,
    ) -> Result<Self, CommunicatorError> {
        let server_uri = Uri::from_str(&format!("https://{}:{}", &hostname, port))?;
        let client_tls_config = ClientTlsConfig::new()
            .domain_name(hostname)
            .ca_certificate(certificate);
        let channel = Channel::builder(server_uri)
            .tls_config(client_tls_config)?
            .connect()
            .await?;
        let client = MpcClient::new(channel);
        Ok(Self { client })
    }
}

#[async_trait]
impl Communicator for Meesign {
    async fn get_groups(&mut self) -> Result<Vec<Group>, CommunicatorError> {
        let request = tonic::Request::new(GroupsRequest { device_id: None });

        let response = self.client.get_groups(request).await?;
        let groups = &response.get_ref().groups;
        let groups = groups
            .iter()
            .filter(|group| group.key_type == KeyType::SignChallenge as i32)
            .map(|group| Group::new(group.identifier.clone(), group.name.clone()))
            .collect();
        Ok(groups)
    }

    async fn send_auth_request(
        &mut self,
        group_id: GroupId,
        data: RequestData,
        request_originator: Option<String>,
    ) -> Result<TaskId, CommunicatorError> {
        let task_name_provider = TaskNameProvider::new();
        let task_name = task_name_provider.get_task_name(request_originator);
        let request = tonic::Request::new(SignRequest {
            name: task_name,
            group_id,
            data,
        });
        let response = self.client.sign(request).await?;

        Ok(response.get_ref().id.clone())
    }

    async fn get_auth_response(
        &mut self,
        task_id: TaskId,
    ) -> Result<Option<AuthResponse>, CommunicatorError> {
        for _ in 1..1000 {
            // NOTE: Waiting in the beginning is counterintuitive, but we know that we will likely
            // wait due to the roundtrips between MeeSign Server and Clients and therefore can
            // afford to wait and hope that a single wait will be enough.
            time::sleep(Duration::from_millis(10)).await;
            let request = tonic::Request::new(TaskRequest {
                task_id: task_id.clone(),
                device_id: None,
            });
            let response = self.client.get_task(request).await?;
            if response.get_ref().state == TaskState::Finished as i32 {
                return Ok(response.get_ref().data.to_owned());
            }
            if response.get_ref().state == TaskState::Failed as i32 {
                return Err(CommunicatorError::TaskFailed);
            }
        }

        Err(CommunicatorError::TaskTimedOut(
            MAX_ATTEMPT_COUNT as u64, // ((MAX_ATTEMPT_COUNT as f64) * ATTEMPT_SLEEP_SEC).round() as u64,
        ))
    }
}
