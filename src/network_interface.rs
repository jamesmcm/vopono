use anyhow::{anyhow, Context};
use log::debug;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::str::FromStr;

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
}

impl NetworkInterface {
    pub fn new(name: String) -> anyhow::Result<Self> {
        Ok(Self { name })
    }
}

impl FromStr for NetworkInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let interfaces = get_active_interfaces()?;

        if interfaces.iter().any(|x| x == s) {
            Ok(Self {
                name: String::from(s),
            })
        } else {
            Err(anyhow!("{} is not an active interface!", s))
        }
    }
}

pub fn get_active_interfaces() -> anyhow::Result<Vec<String>> {
    debug!("ip addr");
    let output = Command::new("ip")
        .arg("addr")
        .output()
        .with_context(|| "Failed to run command: ip addr".to_string())?
        .stdout;

    let out = std::str::from_utf8(&output)?
        .split('\n')
        .filter(|x| x.contains("state UP"))
        .map(|x| x.split_whitespace().nth(1))
        .filter(|x| x.is_some())
        .map(|x| x.unwrap())
        .map(|x| String::from(&x[..x.len() - 1]))
        .collect::<Vec<String>>();

    if !out.is_empty() {
        Ok(out)
    } else {
        Err(anyhow!("Failed to get active network interface"))
    }
}
