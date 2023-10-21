use super::communicator_error::CommunicatorError;
use crate::configuration_provider::controller_configuration::EffectiveInterfaceType;

pub(crate) struct TaskNameProvider {}

impl TaskNameProvider {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn get_task_name(&self, originator: Option<String>) -> String {
        let effective_interface_type = EffectiveInterfaceType::from_environment();
        let binary_name = self.get_binary_name().unwrap_or(None);

        let request_info = Some(format!("{effective_interface_type} authentication request"));
        let mut binary_info = binary_name.map(|binary_name| format!("using {}", binary_name));
        let originator_info = originator.map(|originator| format!("for {originator}"));

        if effective_interface_type == EffectiveInterfaceType::WebAuthn {
            // there is no need to say, that a WebAuthn task was created using softfido
            binary_info = None;
        };

        let task_parts = vec![request_info, binary_info, originator_info];
        let task_parts_joined = task_parts
            .into_iter()
            .filter_map(|part| part)
            .collect::<Vec<String>>()
            .join(" ");
        let task_name = format!("{task_parts_joined}.");
        task_name
    }

    #[cfg(target_os = "linux")]
    fn get_binary_name(&self) -> Result<Option<String>, CommunicatorError> {
        use procfs::process::Process;

        let this_process = Process::myself()?;
        let process_name = this_process.stat()?.comm;
        Ok(Some(process_name))
    }

    #[cfg(target_os = "windows")]
    fn get_binary_name(&self) -> Result<String, CommunicatorError> {
        // TODO: this is very unreliable, even worse than procfs for Linux
        let filename = std::env::current_exe()?.file_name();
        Ok(filename)
    }
}
