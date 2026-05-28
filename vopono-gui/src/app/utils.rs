use eframe::egui;
#[cfg(test)]
use std::collections::HashSet;

pub(super) const LAUNCH_CUSTOM_SCROLL_ID: &str = "launch_custom_configs_scroll";
pub(super) const LAUNCH_APPS_SCROLL_ID: &str = "launch_apps_scroll";
pub(super) const FILE_PICKER_SCROLL_ID: &str = "file_picker_scroll";
pub(super) const PROVIDERS_SCROLL_ID: &str = "providers_scroll";
pub(super) const CUSTOM_CONFIGS_SCROLL_ID: &str = "custom_configs_scroll";
pub(super) const ADDED_APPS_SCROLL_ID: &str = "added_apps_scroll";
pub(super) const DISCOVERED_APPS_SCROLL_ID: &str = "discovered_apps_scroll";

#[cfg(test)]
const SCROLL_IDS: [&str; 7] = [
    LAUNCH_CUSTOM_SCROLL_ID,
    LAUNCH_APPS_SCROLL_ID,
    FILE_PICKER_SCROLL_ID,
    PROVIDERS_SCROLL_ID,
    CUSTOM_CONFIGS_SCROLL_ID,
    ADDED_APPS_SCROLL_ID,
    DISCOVERED_APPS_SCROLL_ID,
];

pub(super) fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    text.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u16>()
                .map_err(|_| format!("Invalid port '{part}'"))
        })
        .collect()
}

pub(super) fn detail_label(ui: &mut egui::Ui, text: impl AsRef<str>) {
    let text = text.as_ref();
    ui.add(egui::Label::new(egui::RichText::new(shorten_middle(text, 140)).small()).truncate())
        .on_hover_text(text);
}

fn shorten_middle(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        return text.to_string();
    }

    let keep = max_chars.saturating_sub(3);
    let start_len = keep / 2;
    let end_len = keep - start_len;
    let start = text.chars().take(start_len).collect::<String>();
    let end = text
        .chars()
        .rev()
        .take(end_len)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{start}...{end}")
}

pub(super) fn has_files(path: &std::path::Path) -> bool {
    path.read_dir()
        .is_ok_and(|mut entries| entries.any(|entry| entry.is_ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_area_ids_are_unique() {
        let unique = SCROLL_IDS.iter().copied().collect::<HashSet<_>>();
        assert_eq!(unique.len(), SCROLL_IDS.len());
    }

    #[test]
    fn long_detail_labels_are_bounded() {
        let long = "/very/long/path/".repeat(40);
        let shortened = shorten_middle(&long, 140);
        assert!(shortened.chars().count() <= 140);
        assert!(shortened.contains("..."));
    }

    #[test]
    fn parse_ports_accepts_commas_and_whitespace() {
        assert_eq!(
            parse_ports("8080, 9090 10000").unwrap(),
            vec![8080, 9090, 10000]
        );
        assert_eq!(format_ports(&[8080, 9090]), "8080, 9090");
    }

    #[test]
    fn parse_ports_rejects_invalid_values() {
        assert!(parse_ports("8080, nope").is_err());
        assert!(parse_ports("70000").is_err());
    }
}
