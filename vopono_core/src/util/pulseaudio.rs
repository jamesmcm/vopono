use anyhow::anyhow;
use log::debug;
use regex::Regex;
use std::process::Command;

pub fn get_pulseaudio_server() -> anyhow::Result<String> {
    let output = Command::new("pactl")
        .args(["-f", "json", "info"])
        .output()?
        .stdout;
    let re = Regex::new("\"server_string\":\"([^\"]+)\"").unwrap();
    let output = std::str::from_utf8(&output)?;

    let caps = re.captures(output);
    if caps.is_none() {
        return Err(anyhow!("Could not parse pactl output!:\n{}", output));
    }
    let caps = caps.unwrap().get(1);
    if caps.is_none() {
        return Err(anyhow!("Could not parse pactl output!:\n{}", output));
    }

    let out = caps.unwrap().as_str().to_string();
    debug!("Setting PULSE_SERVER to {}", out);
    Ok(out)
}
