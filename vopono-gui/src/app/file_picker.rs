use std::path::{Path, PathBuf};

#[derive(Clone)]
pub(super) struct FilePickerEntry {
    pub(super) name: String,
    pub(super) path: PathBuf,
    pub(super) is_dir: bool,
}

pub(super) struct FilePicker {
    pub(super) open: bool,
    pub(super) current_dir: PathBuf,
    pub(super) entries: Vec<FilePickerEntry>,
    pub(super) selected: usize,
    pub(super) error: Option<String>,
}

impl FilePicker {
    pub(super) fn new() -> Self {
        let current_dir = default_picker_dir();
        let mut picker = Self {
            open: false,
            current_dir,
            entries: Vec::new(),
            selected: 0,
            error: None,
        };
        picker.refresh();
        picker
    }

    pub(super) fn open_at_default(&mut self) {
        if !self.current_dir.exists() {
            self.current_dir = default_picker_dir();
        }
        self.open = true;
        self.refresh();
    }

    pub(super) fn go_home(&mut self) {
        self.current_dir = default_picker_dir();
        self.refresh();
    }

    pub(super) fn go_up(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.current_dir = parent.to_path_buf();
            self.refresh();
        }
    }

    pub(super) fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let current = self.selected as isize;
        let len = self.entries.len() as isize;
        self.selected = (current + delta).rem_euclid(len) as usize;
    }

    pub(super) fn activate_selected(&mut self) -> Option<PathBuf> {
        let entry = self.entries.get(self.selected)?.clone();
        if entry.is_dir {
            self.current_dir = entry.path;
            self.refresh();
            None
        } else {
            self.open = false;
            Some(entry.path)
        }
    }

    fn refresh(&mut self) {
        self.entries.clear();
        self.error = None;

        let read_dir = match std::fs::read_dir(&self.current_dir) {
            Ok(read_dir) => read_dir,
            Err(error) => {
                self.error = Some(error.to_string());
                return;
            }
        };

        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                dirs.push(FilePickerEntry {
                    name,
                    path,
                    is_dir: true,
                });
            } else if is_vpn_config_file(&path) {
                files.push(FilePickerEntry {
                    name,
                    path,
                    is_dir: false,
                });
            }
        }

        dirs.sort_by(|a, b| a.name.cmp(&b.name));
        files.sort_by(|a, b| a.name.cmp(&b.name));
        self.entries.extend(dirs);
        self.entries.extend(files);
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
    }
}

fn default_picker_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn is_vpn_config_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "conf" | "ovpn"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_picker_accepts_only_vpn_config_extensions() {
        assert!(is_vpn_config_file(Path::new("airvpn.conf")));
        assert!(is_vpn_config_file(Path::new("airvpn.ovpn")));
        assert!(!is_vpn_config_file(Path::new("airvpn.txt")));
    }

    #[test]
    fn move_selection_wraps_in_both_directions() {
        let mut picker = FilePicker {
            open: true,
            current_dir: PathBuf::from("/tmp"),
            entries: vec![
                FilePickerEntry {
                    name: "a.conf".to_string(),
                    path: PathBuf::from("/tmp/a.conf"),
                    is_dir: false,
                },
                FilePickerEntry {
                    name: "b.conf".to_string(),
                    path: PathBuf::from("/tmp/b.conf"),
                    is_dir: false,
                },
            ],
            selected: 0,
            error: None,
        };

        picker.move_selection(-1);
        assert_eq!(picker.selected, 1);
        picker.move_selection(1);
        assert_eq!(picker.selected, 0);
    }
}
