mod file_picker;
mod input;
mod screens;
mod utils;
mod vpn;

use crate::desktop::{DesktopApplication, scan_desktop_applications};
use crate::gui_config::{
    ApplicationEnvVar, ApplicationProfile, CustomVpnConfig, GuiConfig, ProviderForwardedPort,
    VpnConfigUsage, gui_config_path, load_gui_config, load_vopono_config_text,
    read_provider_forwarded_port, save_gui_config, vopono_config_path,
};
use crate::launcher::pipe_child_output;
use crate::status::{StatusSnapshot, read_status};
use crate::tray::{TrayCommand, TrayManager};
use eframe::egui;
use file_picker::FilePicker;
use gilrs::Gilrs;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use utils::{format_ports, parse_ports};
use vopono_core::util::get_config_file_protocol;
use vpn::{VpnChoice, launch_vpn_choice, scan_synced_configs, vpn_choices_from_configs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum View {
    Launch,
    Config,
    Providers,
    Applications,
    Status,
    Logs,
}

impl View {
    const ALL: [Self; 6] = [
        Self::Launch,
        Self::Config,
        Self::Providers,
        Self::Applications,
        Self::Status,
        Self::Logs,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Launch => "Launch",
            Self::Config => "Config",
            Self::Providers => "Providers",
            Self::Applications => "Applications",
            Self::Status => "Status",
            Self::Logs => "Logs",
        }
    }
}

struct ActiveLaunch {
    child: Child,
    log_id: u64,
}

#[derive(Clone, Debug)]
pub(super) struct LaunchLog {
    id: u64,
    title: String,
    lines: Vec<String>,
    running: bool,
}

pub struct VoponoGuiApp {
    current_view: View,
    gui_config_path: PathBuf,
    vopono_config_path: PathBuf,
    gui_config: GuiConfig,
    config_text: String,
    desktop_apps: Vec<DesktopApplication>,
    synced_configs: Vec<vpn::SyncedVpnConfig>,
    selected_vpn_key: Option<String>,
    selected_app_cmd: Option<String>,
    active_children: Vec<ActiveLaunch>,
    log_sender: Sender<(u64, String)>,
    log_receiver: Receiver<(u64, String)>,
    logs: Vec<LaunchLog>,
    next_log_id: u64,
    file_picker: FilePicker,
    new_custom_name: String,
    new_custom_path: String,
    new_app_name: String,
    new_app_command: String,
    new_app_args: String,
    new_app_env_vars: String,
    app_env_edit_text: BTreeMap<String, String>,
    open_ports_text: String,
    provider_forwarded_port: Option<ProviderForwardedPort>,
    status: StatusSnapshot,
    tray: TrayManager,
    logo_texture: Option<egui::TextureHandle>,
    gilrs: Option<Gilrs>,
    last_status_refresh: Instant,
    message: Option<String>,
    error: Option<String>,
    should_quit: bool,
}

impl VoponoGuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let gui_config_path = gui_config_path().unwrap_or_else(|_| PathBuf::from("gui.toml"));
        let vopono_config_path =
            vopono_config_path().unwrap_or_else(|_| PathBuf::from("config.toml"));
        let gui_config = load_gui_config(&gui_config_path).unwrap_or_default();
        let open_ports_text = format_ports(&gui_config.launch.open_ports);
        let config_text = load_vopono_config_text(&vopono_config_path).unwrap_or_default();
        let provider_forwarded_port = read_provider_forwarded_port().unwrap_or_default();
        let status = read_status();
        let tray = TrayManager::new(&status);
        let logo_texture = crate::brand::logo_texture_image().ok().map(|image| {
            cc.egui_ctx
                .load_texture("vopono-badge", image, egui::TextureOptions::LINEAR)
        });
        let gilrs = Gilrs::new().ok();
        let (log_sender, log_receiver) = std::sync::mpsc::channel();
        let app_env_edit_text = gui_config
            .applications
            .iter()
            .map(|app| (app.command.clone(), app.env_line()))
            .collect();

        let mut app = Self {
            current_view: View::Launch,
            gui_config_path,
            vopono_config_path,
            gui_config,
            config_text,
            desktop_apps: scan_desktop_applications(),
            synced_configs: scan_synced_configs(),
            selected_vpn_key: None,
            selected_app_cmd: None,
            active_children: Vec::new(),
            log_sender,
            log_receiver,
            logs: Vec::new(),
            next_log_id: 1,
            file_picker: FilePicker::new(),
            new_custom_name: String::new(),
            new_custom_path: String::new(),
            new_app_name: String::new(),
            new_app_command: String::new(),
            new_app_args: String::new(),
            new_app_env_vars: String::new(),
            app_env_edit_text,
            open_ports_text,
            provider_forwarded_port,
            status,
            tray,
            logo_texture,
            gilrs,
            last_status_refresh: Instant::now(),
            message: None,
            error: None,
            should_quit: false,
        };
        app.sort_applications();
        app.select_default_launch_targets();
        app
    }

    fn save_gui_config(&mut self) {
        match save_gui_config(&self.gui_config_path, &self.gui_config) {
            Ok(()) => self.message = Some("Saved GUI configuration".to_string()),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn refresh_status(&mut self) {
        self.status = read_status();
        self.provider_forwarded_port = read_provider_forwarded_port().unwrap_or_default();
        self.tray.update_status(&self.status);
        self.last_status_refresh = Instant::now();
    }

    fn add_custom_config(&mut self) {
        let path = PathBuf::from(self.new_custom_path.trim());
        self.add_custom_config_path(path);
    }

    fn add_custom_config_path(&mut self, path: PathBuf) {
        if path.as_os_str().is_empty() {
            self.error = Some("Custom config path is required".to_string());
            return;
        }

        let protocol = match get_config_file_protocol(&path) {
            Ok(protocol) => protocol.to_string(),
            Err(error) => {
                self.error = Some(format!("Could not detect protocol: {error}"));
                return;
            }
        };
        if self
            .gui_config
            .custom_vpn_configs
            .iter()
            .any(|config| config.path == path)
        {
            self.error = Some(format!("Custom config already exists: {}", path.display()));
            return;
        }
        let name = if self.new_custom_name.trim().is_empty() {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("Custom VPN")
                .to_string()
        } else {
            self.new_custom_name.trim().to_string()
        };

        self.gui_config.custom_vpn_configs.push(CustomVpnConfig {
            name,
            path,
            protocol,
            usage_count: 0,
        });
        self.new_custom_name.clear();
        self.new_custom_path.clear();
        self.select_default_launch_targets();
        self.save_gui_config();
    }

    fn add_manual_app(&mut self) {
        if self.new_app_name.trim().is_empty() || self.new_app_command.trim().is_empty() {
            self.error = Some("Application name and command are required".to_string());
            return;
        }
        let command = self.new_app_command.trim().to_string();
        let env_vars = match parse_env_vars(&self.new_app_env_vars) {
            Ok(env_vars) => {
                merge_env_vars(crate::desktop::env_vars_for_command(&command), env_vars)
            }
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        if self
            .gui_config
            .applications
            .iter()
            .any(|existing| existing.command == command)
        {
            self.error = Some(format!("Application command already exists: {command}"));
            return;
        }

        self.gui_config.applications.push(ApplicationProfile {
            name: self.new_app_name.trim().to_string(),
            command: command.clone(),
            args: self
                .new_app_args
                .split_whitespace()
                .map(ToString::to_string)
                .collect(),
            env_vars,
            working_directory: None,
            usage_count: 0,
        });
        self.new_app_name.clear();
        self.new_app_command.clear();
        self.new_app_args.clear();
        self.new_app_env_vars.clear();
        if let Some(app) = self
            .gui_config
            .applications
            .iter()
            .find(|app| app.command == command)
        {
            self.app_env_edit_text
                .insert(app.command.clone(), app.env_line());
        }
        self.sort_applications();
        self.select_default_launch_targets();
        self.save_gui_config();
    }

    fn add_desktop_app(&mut self, index: usize) {
        if let Some(app) = self.desktop_apps.get(index) {
            let profile = app.profile();
            if !self
                .gui_config
                .applications
                .iter()
                .any(|existing| existing.command == profile.command)
            {
                self.gui_config.applications.push(profile);
                if let Some(app) = self.gui_config.applications.last() {
                    self.app_env_edit_text
                        .insert(app.command.clone(), app.env_line());
                }
                self.sort_applications();
                self.select_default_launch_targets();
                self.save_gui_config();
            }
        }
    }

    fn sort_applications(&mut self) {
        self.gui_config.applications.sort_by(|a, b| {
            b.usage_count
                .cmp(&a.usage_count)
                .then_with(|| a.name.cmp(&b.name))
        });
    }

    fn select_default_launch_targets(&mut self) {
        let vpn_choices = self.vpn_choices();
        if !self.selected_vpn_key.as_ref().is_some_and(|key| {
            vpn_choices
                .iter()
                .any(|choice| choice.key() == key.as_str() && !choice.is_missing())
        }) {
            self.selected_vpn_key = vpn_choices
                .iter()
                .find(|choice| !choice.is_missing())
                .map(VpnChoice::key);
        }

        if !self.selected_app_cmd.as_ref().is_some_and(|command| {
            self.gui_config
                .applications
                .iter()
                .any(|app| app.command == command.as_str())
        }) {
            self.selected_app_cmd = self
                .gui_config
                .applications
                .first()
                .map(|app| app.command.clone());
        }
    }

    fn vpn_usage_count(&self, choice: &VpnChoice) -> u64 {
        match choice {
            VpnChoice::Custom { config, .. } => config.usage_count,
            VpnChoice::Synced(_) => {
                let key = choice.key();
                self.gui_config
                    .vpn_config_usage
                    .iter()
                    .find(|usage| usage.key == key)
                    .map(|usage| usage.usage_count)
                    .unwrap_or(0)
            }
        }
    }

    fn increment_vpn_usage(&mut self, choice: &VpnChoice) {
        match choice {
            VpnChoice::Custom { index, .. } => {
                if let Some(config) = self.gui_config.custom_vpn_configs.get_mut(*index) {
                    config.usage_count += 1;
                }
            }
            VpnChoice::Synced(_) => {
                let key = choice.key();
                if let Some(usage) = self
                    .gui_config
                    .vpn_config_usage
                    .iter_mut()
                    .find(|usage| usage.key == key)
                {
                    usage.usage_count += 1;
                } else {
                    self.gui_config.vpn_config_usage.push(VpnConfigUsage {
                        key,
                        usage_count: 1,
                    });
                }
            }
        }
    }

    fn launch_selected(&mut self) {
        if !self.sync_launch_options_from_ui() {
            return;
        }

        let vpn_choices = self.vpn_choices();
        let Some(vpn_key) = self.selected_vpn_key.as_deref() else {
            self.error = Some("Choose a VPN config first".to_string());
            return;
        };
        let Some(app_command) = self.selected_app_cmd.clone() else {
            self.error = Some("Choose an application first".to_string());
            return;
        };
        let Some(vpn_choice) = vpn_choices
            .iter()
            .find(|choice| choice.key() == vpn_key)
            .cloned()
        else {
            self.error = Some("Selected VPN config no longer exists".to_string());
            return;
        };
        let Some(app) = self
            .gui_config
            .applications
            .iter()
            .find(|app| app.command == app_command)
            .cloned()
        else {
            self.error = Some("Selected application no longer exists".to_string());
            return;
        };

        match launch_vpn_choice(&vpn_choice, &app, &self.gui_config.launch) {
            Ok(result) => {
                let log_id = self.next_log_id;
                self.next_log_id += 1;
                let mut child = result.child;
                pipe_child_output(log_id, &mut child, self.log_sender.clone());
                self.logs.push(LaunchLog {
                    id: log_id,
                    title: format!("{}: {}", app.name, result.command_line),
                    lines: vec![format!("$ {}", result.command_line)],
                    running: true,
                });
                self.active_children.push(ActiveLaunch { child, log_id });
                self.increment_vpn_usage(&vpn_choice);
                if let Some(app) = self
                    .gui_config
                    .applications
                    .iter_mut()
                    .find(|app| app.command == app_command)
                {
                    app.usage_count += 1;
                }
                self.sort_applications();
                self.save_gui_config();
                self.message = Some(result.message);
                self.refresh_status();
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn refresh_synced_configs(&mut self) {
        self.synced_configs = scan_synced_configs();
        self.select_default_launch_targets();
    }

    fn remove_custom_config(&mut self, index: usize) {
        if index >= self.gui_config.custom_vpn_configs.len() {
            self.error = Some("Custom VPN config no longer exists".to_string());
            return;
        }

        let removed = self.gui_config.custom_vpn_configs.remove(index);
        self.select_default_launch_targets();
        self.save_gui_config();
        self.message = Some(format!(
            "Deleted launch config '{}'; the VPN file was not deleted",
            removed.name
        ));
    }

    fn vpn_choices(&self) -> Vec<VpnChoice> {
        let mut choices =
            vpn_choices_from_configs(&self.gui_config.custom_vpn_configs, &self.synced_configs);
        choices.sort_by(|a, b| {
            self.vpn_usage_count(b)
                .cmp(&self.vpn_usage_count(a))
                .then_with(|| a.primary_label().cmp(&b.primary_label()))
        });
        choices
    }

    fn sync_launch_options_from_ui(&mut self) -> bool {
        match parse_ports(&self.open_ports_text) {
            Ok(open_ports) => {
                self.gui_config.launch.open_ports = open_ports;
                true
            }
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }

    fn save_launch_options(&mut self) {
        if self.sync_launch_options_from_ui() {
            self.save_gui_config();
        }
    }

    fn drain_log_output(&mut self) {
        while let Ok((log_id, line)) = self.log_receiver.try_recv() {
            if let Some(log) = self.logs.iter_mut().find(|log| log.id == log_id) {
                log.lines.push(line);
            }
        }
    }
}

impl eframe::App for VoponoGuiApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) && !self.should_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        if self.should_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.handle_shortcuts(ctx);
        self.handle_gamepad(ctx);
        self.drain_log_output();
        let mut finished = Vec::new();
        self.active_children
            .retain_mut(|launch| match launch.child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    finished.push((launch.log_id, format!("process exited with {status}")));
                    false
                }
                Err(error) => {
                    finished.push((launch.log_id, format!("failed to poll process: {error}")));
                    false
                }
            });
        for (log_id, line) in finished {
            if let Some(log) = self.logs.iter_mut().find(|log| log.id == log_id) {
                log.running = false;
                log.lines.push(line);
            }
        }
        self.tray.pump_events();
        if self.last_status_refresh.elapsed() >= Duration::from_secs(5) {
            self.refresh_status();
        }
        while let Some(command) = self.tray.poll_command() {
            match command {
                TrayCommand::Show => ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true)),
                TrayCommand::Hide => ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false)),
                TrayCommand::Quit => self.should_quit = true,
            }
        }

        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.main_ui(ui, frame);
    }
}

fn parse_env_vars(input: &str) -> Result<Vec<ApplicationEnvVar>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let words = shell_words::split(input).map_err(|error| format!("Invalid env vars: {error}"))?;
    words
        .into_iter()
        .map(|word| {
            let Some((key, value)) = word.split_once('=') else {
                return Err(format!("Env var must be KEY=VALUE: {word}"));
            };
            let key = key.trim();
            if key.is_empty() {
                return Err("Env var key cannot be empty".to_string());
            }
            Ok(ApplicationEnvVar {
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

fn merge_env_vars(
    mut defaults: Vec<ApplicationEnvVar>,
    custom: Vec<ApplicationEnvVar>,
) -> Vec<ApplicationEnvVar> {
    for env_var in custom {
        if let Some(existing) = defaults.iter_mut().find(|item| item.key == env_var.key) {
            existing.value = env_var.value;
        } else {
            defaults.push(env_var);
        }
    }
    defaults
}
