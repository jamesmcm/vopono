mod file_picker;
mod input;
mod screens;
mod utils;
mod vpn;

use crate::desktop::{DesktopApplication, scan_desktop_applications};
use crate::gui_config::{
    ApplicationProfile, CustomVpnConfig, GuiConfig, gui_config_path, load_gui_config,
    load_vopono_config_text, save_gui_config, vopono_config_path,
};
use crate::status::{StatusSnapshot, read_status};
use crate::tray::{TrayCommand, TrayManager};
use eframe::egui;
use file_picker::FilePicker;
use gilrs::Gilrs;
use std::path::PathBuf;
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
}

impl View {
    const ALL: [Self; 5] = [
        Self::Launch,
        Self::Config,
        Self::Providers,
        Self::Applications,
        Self::Status,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Launch => "Launch",
            Self::Config => "Config",
            Self::Providers => "Providers",
            Self::Applications => "Applications",
            Self::Status => "Status",
        }
    }
}

pub struct VoponoGuiApp {
    current_view: View,
    gui_config_path: PathBuf,
    vopono_config_path: PathBuf,
    gui_config: GuiConfig,
    config_text: String,
    desktop_apps: Vec<DesktopApplication>,
    synced_configs: Vec<vpn::SyncedVpnConfig>,
    selected_vpn: Option<usize>,
    selected_app: Option<usize>,
    file_picker: FilePicker,
    new_custom_name: String,
    new_custom_path: String,
    new_app_name: String,
    new_app_command: String,
    new_app_args: String,
    open_ports_text: String,
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
        let status = read_status();
        let tray = TrayManager::new(&status);
        // TODO: Fix logo to remove white background and vopono text (just icon)
        let logo_texture = crate::brand::logo_texture_image().ok().map(|image| {
            cc.egui_ctx
                .load_texture("vopono-logo", image, egui::TextureOptions::LINEAR)
        });
        let gilrs = Gilrs::new().ok();

        Self {
            current_view: View::Launch,
            gui_config_path,
            vopono_config_path,
            gui_config,
            config_text,
            desktop_apps: scan_desktop_applications(),
            synced_configs: scan_synced_configs(),
            selected_vpn: None,
            selected_app: None,
            file_picker: FilePicker::new(),
            new_custom_name: String::new(),
            new_custom_path: String::new(),
            new_app_name: String::new(),
            new_app_command: String::new(),
            new_app_args: String::new(),
            open_ports_text,
            status,
            tray,
            logo_texture,
            gilrs,
            last_status_refresh: Instant::now(),
            message: None,
            error: None,
            should_quit: false,
        }
    }

    fn save_gui_config(&mut self) {
        match save_gui_config(&self.gui_config_path, &self.gui_config) {
            Ok(()) => self.message = Some("Saved GUI configuration".to_string()),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn refresh_status(&mut self) {
        self.status = read_status();
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
        self.save_gui_config();
    }

    fn add_manual_app(&mut self) {
        if self.new_app_name.trim().is_empty() || self.new_app_command.trim().is_empty() {
            self.error = Some("Application name and command are required".to_string());
            return;
        }

        self.gui_config.applications.push(ApplicationProfile {
            name: self.new_app_name.trim().to_string(),
            command: self.new_app_command.trim().to_string(),
            args: self
                .new_app_args
                .split_whitespace()
                .map(ToString::to_string)
                .collect(),
            working_directory: None,
            usage_count: 0,
        });
        self.new_app_name.clear();
        self.new_app_command.clear();
        self.new_app_args.clear();
        self.sort_applications();
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
                self.sort_applications();
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

    fn launch_selected(&mut self) {
        if !self.sync_launch_options_from_ui() {
            return;
        }

        let vpn_choices = self.vpn_choices();
        let Some(vpn_index) = self.selected_vpn else {
            self.error = Some("Choose a VPN config first".to_string());
            return;
        };
        let Some(app_index) = self.selected_app else {
            self.error = Some("Choose an application first".to_string());
            return;
        };
        let Some(vpn_choice) = vpn_choices.get(vpn_index).cloned() else {
            self.error = Some("Selected VPN config no longer exists".to_string());
            return;
        };
        let Some(app) = self.gui_config.applications.get(app_index).cloned() else {
            self.error = Some("Selected application no longer exists".to_string());
            return;
        };

        match launch_vpn_choice(&vpn_choice, &app, &self.gui_config.launch) {
            Ok(message) => {
                if let VpnChoice::Custom { index, .. } = vpn_choice
                    && let Some(config) = self.gui_config.custom_vpn_configs.get_mut(index)
                {
                    config.usage_count += 1;
                }
                if let Some(app) = self.gui_config.applications.get_mut(app_index) {
                    app.usage_count += 1;
                }
                self.sort_applications();
                self.save_gui_config();
                self.message = Some(message);
                self.refresh_status();
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn refresh_synced_configs(&mut self) {
        self.synced_configs = scan_synced_configs();
        if let Some(selected) = self.selected_vpn
            && selected >= self.vpn_choices().len()
        {
            self.selected_vpn = None;
        }
    }

    fn vpn_choices(&self) -> Vec<VpnChoice> {
        vpn_choices_from_configs(&self.gui_config.custom_vpn_configs, &self.synced_configs)
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
