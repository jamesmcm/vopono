use super::NetworkNamespace;

pub struct ApplicationWrapper {
    handle: std::process::Child,
}

impl ApplicationWrapper {
    pub fn new(
        netns: &NetworkNamespace,
        application: &str,
        user: Option<String>,
    ) -> anyhow::Result<Self> {
        let handle = netns.exec_no_block(
            application
                .split_whitespace()
                .collect::<Vec<_>>()
                .as_slice(),
            user,
        )?;
        Ok(Self { handle })
    }

    pub fn wait_with_output(self) -> anyhow::Result<std::process::Output> {
        let output = self.handle.wait_with_output()?;
        Ok(output)
    }

    pub fn check_if_running(&mut self) -> anyhow::Result<bool> {
        let output = self.handle.try_wait()?;

        Ok(output.is_none())
    }
}
