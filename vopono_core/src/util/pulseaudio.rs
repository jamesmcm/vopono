use anyhow::anyhow;
use log::debug;
use regex::Regex;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PACTL_TIMEOUT: Duration = Duration::from_secs(1);

pub fn get_pulseaudio_server() -> anyhow::Result<String> {
    let mut child = Command::new("pactl")
        .args(["-f", "json", "info"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + PACTL_TIMEOUT;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("Timed out querying pactl for PulseAudio server"));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if !status.success() {
        return Err(anyhow!("pactl exited with {status}"));
    }
    let mut output = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout.take(256 * 1024).read_to_end(&mut output)?;
    }
    let re = Regex::new("\"server_string\":\"([^\"]+)\"").unwrap();
    let output = std::str::from_utf8(&output)?;

    let caps = re.captures(output);
    if caps.is_none() {
        return Err(anyhow!("Could not parse pactl output!:\n{output}"));
    }
    let caps = caps.unwrap().get(1);
    if caps.is_none() {
        return Err(anyhow!("Could not parse pactl output!:\n{output}"));
    }

    let out = caps.unwrap().as_str().to_string();
    debug!("Setting PULSE_SERVER to {out}");
    Ok(out)
}
