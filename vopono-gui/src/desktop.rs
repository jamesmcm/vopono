use crate::gui_config::ApplicationProfile;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Clone, Debug)]
pub struct DesktopApplication {
    pub name: String,
    pub command: String,
    pub source: PathBuf,
}

impl DesktopApplication {
    pub fn profile(&self) -> ApplicationProfile {
        ApplicationProfile {
            name: self.name.clone(),
            command: self.command.clone(),
            args: Vec::new(),
            working_directory: None,
            usage_count: 0,
        }
    }
}

pub fn scan_desktop_applications() -> Vec<DesktopApplication> {
    let mut apps = BTreeMap::<String, DesktopApplication>::new();

    for dir in application_dirs() {
        if !dir.exists() {
            continue;
        }

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "desktop"))
        {
            if let Some(app) = parse_desktop_file(entry.path()) {
                apps.entry(app.name.to_lowercase()).or_insert(app);
            }
        }
    }

    apps.into_values().collect()
}

fn application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(xdg_data_home) = std::env::var("XDG_DATA_HOME") {
        dirs.push(PathBuf::from(xdg_data_home).join("applications"));
    } else if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }

    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_string());
    dirs.extend(
        data_dirs
            .split(':')
            .filter(|path| !path.is_empty())
            .map(|path| PathBuf::from(path).join("applications")),
    );

    dirs
}

fn parse_desktop_file(path: &Path) -> Option<DesktopApplication> {
    let raw = std::fs::read_to_string(path).ok()?;
    let mut in_entry = false;
    let mut name = None;
    let mut exec = None;
    let mut hidden = false;
    let mut no_display = false;
    let mut terminal = false;

    for line in raw.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Name" => name = Some(value.to_string()),
            "Exec" => exec = Some(clean_exec(value)),
            "Hidden" => hidden = value.eq_ignore_ascii_case("true"),
            "NoDisplay" => no_display = value.eq_ignore_ascii_case("true"),
            "Terminal" => terminal = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }

    if hidden || no_display || terminal {
        return None;
    }

    let name = name?;
    let command = exec?;
    if command.is_empty() {
        return None;
    }

    Some(DesktopApplication {
        name,
        command,
        source: path.to_path_buf(),
    })
}

fn clean_exec(exec: &str) -> String {
    exec.split_whitespace()
        .filter(|part| !part.starts_with('%'))
        .map(|part| {
            part.replace("%f", "")
                .replace("%F", "")
                .replace("%u", "")
                .replace("%U", "")
                .replace("%i", "")
                .replace("%c", "")
                .replace("%k", "")
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

// TODO: Add a test for the above with an example .desktop file
