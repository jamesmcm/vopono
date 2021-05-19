use super::NetworkNamespace;
use crate::util::get_all_running_process_names;
use log::warn;

pub struct ApplicationWrapper {
    pub handle: std::process::Child,
}

impl ApplicationWrapper {
    pub fn new(
        netns: &NetworkNamespace,
        application: &str,
        user: Option<String>,
    ) -> anyhow::Result<Self> {
        let running_processes = get_all_running_process_names();
        let app_vec = application.split_whitespace().collect::<Vec<_>>();

        for shared_process_app in [
            "google-chrome-stable",
            "google-chrome-beta",
            "google-chrome",
            "chromium",
            "firefox",
            "firefox-developer-edition",
        ]
        .iter()
        {
            // TODO: Avoid String allocation here
            if app_vec.contains(shared_process_app)
                && running_processes.contains(&shared_process_app.to_string())
            {
                warn!("{} is already running. You must force it to use a separate profile in order to launch a new process!", shared_process_app);
            }
        }

        // TODO: Could allow user to set custom working directory here
        let handle = netns.exec_no_block(app_vec.as_slice(), user, false, false, None)?;
        Ok(Self { handle })
    }

    pub fn wait_with_output(self) -> anyhow::Result<std::process::Output> {
        let output = self.handle.wait_with_output()?;
        Ok(output)
    }
}
