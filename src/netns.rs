use anyhow::Context;
use log::debug;
use std::process::Command;
pub struct NetworkNamespace {
    name: String,
    veth_pair: Option<VethPair>,
}

impl NetworkNamespace {
    pub fn new(name: String) -> anyhow::Result<Self> {
        debug!("sudo ip netns add {}", name.as_str());
        Command::new("sudo")
            .args(&["ip", "netns", "add", name.as_str()])
            .spawn()
            .with_context(|| format!("Failed to create network namespace: {}", &name))?;
        Ok(Self {
            name,
            veth_pair: None,
        })
    }

    pub fn exec(&self, command: &[&str]) -> anyhow::Result<()> {
        debug!("sudo ip netns exec {} {}", &self.name, command.join(" "));
        Command::new("sudo")
            .args(&["ip", "netns", "exec", &self.name])
            .args(command)
            .spawn()?;

        Ok(())
    }

    fn add_loopback(&self) -> anyhow::Result<()> {
        self.exec(&["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])
            .with_context(|| format!("Failed to add loopback adapter in netns: {}", &self.name))?;
        self.exec(&["ip", "link", "set", "lo", "up"])
            .with_context(|| format!("Failed to start networking in netns: {}", &self.name))?;
        Ok(())
    }

    fn add_veth_pair(&mut self) -> anyhow::Result<()> {
        // TODO: Handle if name taken?
        // TODO: Can we share veth dest between namespaces?
        let source = format!("{}_src0", &self.name);
        let dest = format!("{}_dest0", &self.name);
        self.veth_pair = Some(VethPair::new(source, dest, &self)?);
        Ok(())
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        debug!("sudo ip netns delete {}", &self.name);
        Command::new("sudo")
            .args(&["ip", "netns", "delete", &self.name])
            .spawn()
            .expect(&format!(
                "Failed to delete network namespace: {}",
                &self.name
            ));
    }
}

struct VethPair {
    source: String,
    dest: String,
}

impl VethPair {
    fn new(source: String, dest: String, netns: &NetworkNamespace) -> anyhow::Result<Self> {
        debug!(
            "sudo ip link add {} type veth peer name {}",
            dest.as_str(),
            source.as_str()
        );
        Command::new("sudo")
            .args(&[
                "ip",
                "link",
                "add",
                dest.as_str(),
                "type",
                "veth",
                "peer",
                "name",
                source.as_str(),
            ])
            .spawn()
            .with_context(|| format!("Failed to create veth pair {}, {}", &source, &dest))?;

        debug!("sudo ip link set {} up", dest.as_str(),);
        Command::new("sudo")
            .args(&["ip", "link", "set", dest.as_str(), "up"])
            .spawn()
            .with_context(|| format!("Failed to bring up destination veth: {}", &dest))?;

        debug!(
            "sudo ip link set {} netns {} up",
            source.as_str(),
            &netns.name,
        );
        Command::new("sudo")
            .args(&[
                "ip",
                "link",
                "set",
                source.as_str(),
                "netns",
                &netns.name,
                "up",
            ])
            .spawn()
            .with_context(|| format!("Failed to bring up source veth: {}", &dest))?;

        Ok(Self { source, dest })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        debug!("sudo ip link delete {}", &self.dest);
        Command::new("sudo")
            .args(&["ip", "link", "delete", &self.dest])
            .spawn()
            .expect(&format!("Failed to delete veth pair: {}", &self.dest));
    }
}
