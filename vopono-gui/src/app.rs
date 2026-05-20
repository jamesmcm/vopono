use crate::desktop::{DesktopApplication, scan_desktop_applications};
use crate::gui_config::{
    ApplicationProfile, CustomVpnConfig, GuiConfig, LaunchConfig, gui_config_path, load_gui_config,
    load_vopono_config_text, save_gui_config, save_vopono_config_text, vopono_config_path,
};
use crate::launcher;
use crate::status::{StatusSnapshot, read_status};
use crate::tray::{TrayCommand, TrayManager};
use eframe::egui;
use gilrs::{Button, EventType, Gilrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::util::{get_config_file_protocol, get_configs_from_alias};

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
    synced_configs: Vec<SyncedVpnConfig>,
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

    // TODO: Move input handling to separate module, put keyboard and gamepad handling in separate
    // files in that module
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        ctx.input(|input| {
            if input.key_pressed(egui::Key::ArrowDown) {
                self.move_selection(1);
            }
            if input.key_pressed(egui::Key::ArrowUp) {
                self.move_selection(-1);
            }
            if input.key_pressed(egui::Key::Escape) && self.file_picker.open {
                self.file_picker.open = false;
            }
            if input.key_pressed(egui::Key::Enter) && self.file_picker.open {
                if let Some(path) = self.file_picker.activate_selected() {
                    self.add_custom_config_path(path);
                }
            } else if input.key_pressed(egui::Key::Enter) && self.current_view == View::Launch {
                self.launch_selected();
            }
            if input.key_pressed(egui::Key::F5) {
                self.refresh_status();
            }
        });
    }

    fn handle_gamepad(&mut self, ctx: &egui::Context) {
        let Some(gilrs) = self.gilrs.as_mut() else {
            return;
        };

        let should_handle_events = self.gui_config.launch.gamepad_enabled && accepts_gamepad(ctx);
        let mut actions = Vec::new();
        while let Some(event) = gilrs.next_event() {
            if !should_handle_events {
                continue;
            }
            match event.event {
                EventType::ButtonPressed(Button::DPadDown, _) => actions.push(GamepadAction::Down),
                EventType::ButtonPressed(Button::DPadUp, _) => actions.push(GamepadAction::Up),
                EventType::ButtonPressed(Button::South, _) => actions.push(GamepadAction::Launch),
                EventType::ButtonPressed(Button::East, _) => actions.push(GamepadAction::Cancel),
                EventType::ButtonPressed(Button::West, _) => actions.push(GamepadAction::Refresh),
                _ => {}
            }
        }

        for action in actions {
            match action {
                GamepadAction::Down => self.move_selection(1),
                GamepadAction::Up => self.move_selection(-1),
                GamepadAction::Launch => {
                    if self.file_picker.open {
                        if let Some(path) = self.file_picker.activate_selected() {
                            self.add_custom_config_path(path);
                        }
                    } else if self.current_view == View::Launch {
                        self.launch_selected();
                    } else if self.current_view == View::Providers {
                        self.file_picker.open_at_default();
                    }
                }
                GamepadAction::Cancel => self.file_picker.open = false,
                GamepadAction::Refresh => self.refresh_status(),
            }
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.file_picker.open {
            self.file_picker.move_selection(delta);
            return;
        }
        if self.current_view != View::Launch {
            return;
        }
        if self.gui_config.applications.is_empty() {
            return;
        }
        let current = self.selected_app.unwrap_or(0) as isize;
        let len = self.gui_config.applications.len() as isize;
        self.selected_app = Some((current + delta).rem_euclid(len) as usize);
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

const LAUNCH_CUSTOM_SCROLL_ID: &str = "launch_custom_configs_scroll";
const LAUNCH_APPS_SCROLL_ID: &str = "launch_apps_scroll";
const FILE_PICKER_SCROLL_ID: &str = "file_picker_scroll";
const PROVIDERS_SCROLL_ID: &str = "providers_scroll";
const CUSTOM_CONFIGS_SCROLL_ID: &str = "custom_configs_scroll";
const ADDED_APPS_SCROLL_ID: &str = "added_apps_scroll";
const DISCOVERED_APPS_SCROLL_ID: &str = "discovered_apps_scroll";

// TODO: Move test code together? - can this be in test module?
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

enum GamepadAction {
    Down,
    Up,
    Launch,
    Cancel,
    Refresh,
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

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        egui::Panel::top("top_bar").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(texture) = &self.logo_texture {
                    ui.add(
                        egui::Image::new(texture)
                            .fit_to_exact_size(egui::vec2(32.0, 32.0))
                            .maintain_aspect_ratio(true),
                    );
                }
                ui.heading("vopono");
                ui.separator();
                ui.label(format!(
                    "{} active namespace{}",
                    self.status.active_count(),
                    if self.status.active_count() == 1 {
                        ""
                    } else {
                        "s"
                    }
                ));
                if ui.button("Refresh").clicked() {
                    self.refresh_status();
                }
                if ui.button("Hide").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
            });
        });

        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(180.0)
            .show_inside(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("Navigation");
                });
                ui.separator();

                for view in View::ALL {
                    let selected = self.current_view == view;
                    if ui.selectable_label(selected, view.label()).clicked() {
                        self.current_view = view;
                    }
                }
            });

        egui::CentralPanel::default_margins().show_inside(ui, |ui| {
            if let Some(message) = self.message.take() {
                ui.colored_label(egui::Color32::from_rgb(31, 153, 88), message);
            }
            if let Some(error) = self.error.take() {
                ui.colored_label(egui::Color32::from_rgb(220, 64, 64), error);
            }
            if let Some(error) = self.tray.error() {
                ui.colored_label(
                    egui::Color32::from_rgb(190, 128, 24),
                    format!("Tray icon unavailable: {error}"),
                );
            }
            ui.separator();

            match self.current_view {
                View::Launch => self.launch_view(ui),
                View::Config => self.config_view(ui),
                View::Providers => self.providers_view(ui),
                View::Applications => self.applications_view(ui),
                View::Status => self.status_view(ui),
            }
        });

        if let Some(path) = self.file_picker_window(&ctx) {
            self.add_custom_config_path(path);
        }
    }
}

// TODO: Is there an easier way to define the UI tree - something like Glade?
impl VoponoGuiApp {
    fn launch_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Launch");
        let vpn_choices = self.vpn_choices();
        ui.columns(2, |columns| {
            columns[0].vertical(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("VPN configs");
                    if ui.button("Refresh").clicked() {
                        self.refresh_synced_configs();
                    }
                    if ui.button("Add custom file").clicked() {
                        self.file_picker.open_at_default();
                    }
                });
                egui::ScrollArea::vertical()
                    .id_salt(LAUNCH_CUSTOM_SCROLL_ID)
                    .max_height(260.0)
                    .show(ui, |ui| {
                        if vpn_choices.is_empty() {
                            ui.label("No synced or custom VPN configs found.");
                        }
                        for (index, choice) in vpn_choices.iter().enumerate() {
                            let selected = self.selected_vpn == Some(index);
                            if ui
                                .selectable_label(selected, choice.primary_label())
                                .clicked()
                            {
                                self.selected_vpn = Some(index);
                            }
                            detail_label(ui, choice.detail_label());
                        }
                    });
            });
            columns[1].vertical(|ui| {
                ui.label("Applications");
                egui::ScrollArea::vertical()
                    .id_salt(LAUNCH_APPS_SCROLL_ID)
                    .max_height(260.0)
                    .show(ui, |ui| {
                        for (index, app) in self.gui_config.applications.iter().enumerate() {
                            let selected = self.selected_app == Some(index);
                            if ui
                                .selectable_label(
                                    selected,
                                    format!("{} [{}]", app.name, app.usage_count),
                                )
                                .clicked()
                            {
                                self.selected_app = Some(index);
                            }
                            detail_label(ui, app.command_line());
                        }
                    });
            });
        });
        ui.separator();
        ui.heading("Options");
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut self.gui_config.launch.port_forwarding,
                "Provider port forwarding",
            );
            ui.checkbox(
                &mut self.gui_config.launch.gamepad_enabled,
                "Gamepad controls",
            );
        });
        ui.horizontal(|ui| {
            ui.label("Open ports (-o)");
            ui.text_edit_singleline(&mut self.open_ports_text);
            if ui.button("Save options").clicked() {
                self.save_launch_options();
            }
        });
        detail_label(
            ui,
            "Use comma or space separated ports. These options are stored in gui.toml.",
        );
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Launch").clicked() {
                self.launch_selected();
            }
            ui.label("Enter launches. Arrow keys move selection.");
        });
    }

    fn config_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Config");
        ui.label(self.vopono_config_path.display().to_string());
        ui.horizontal(|ui| {
            if ui.button("Reload").clicked() {
                match load_vopono_config_text(&self.vopono_config_path) {
                    Ok(text) => self.config_text = text,
                    Err(error) => self.error = Some(error.to_string()),
                }
            }
            if ui.button("Save").clicked() {
                match save_vopono_config_text(&self.vopono_config_path, &self.config_text) {
                    Ok(()) => self.message = Some("Saved vopono config".to_string()),
                    Err(error) => self.error = Some(error.to_string()),
                }
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.config_text)
                .font(egui::TextStyle::Monospace)
                .desired_rows(28)
                .desired_width(f32::INFINITY),
        );
    }

    fn providers_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Providers");
        ui.label("Built-in providers");
        egui::ScrollArea::vertical()
            .id_salt(PROVIDERS_SCROLL_ID)
            .max_height(180.0)
            .show(ui, |ui| {
                for provider in VpnProvider::iter()
                    .filter(|provider| !matches!(provider, VpnProvider::Custom | VpnProvider::None))
                {
                    ui.group(|ui| {
                        ui.label(provider.to_string());
                        detail_label(ui, provider_config_state(&provider));
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Sync both").clicked() {
                                match launcher::sync_provider(provider.clone(), None) {
                                    Ok(message) => {
                                        self.message = Some(message);
                                        self.refresh_synced_configs();
                                    }
                                    Err(error) => self.error = Some(error.to_string()),
                                }
                            }
                            if ui.button("WireGuard").clicked() {
                                match launcher::sync_provider(
                                    provider.clone(),
                                    Some(Protocol::Wireguard),
                                ) {
                                    Ok(message) => {
                                        self.message = Some(message);
                                        self.refresh_synced_configs();
                                    }
                                    Err(error) => self.error = Some(error.to_string()),
                                }
                            }
                            if ui.button("OpenVPN").clicked() {
                                match launcher::sync_provider(provider, Some(Protocol::OpenVpn)) {
                                    Ok(message) => {
                                        self.message = Some(message);
                                        self.refresh_synced_configs();
                                    }
                                    Err(error) => self.error = Some(error.to_string()),
                                }
                            }
                        });
                    });
                }
            });
        ui.separator();
        ui.label("Custom configs are stored by path, so edits to the original files take effect.");
        ui.horizontal(|ui| {
            ui.label("Name");
            ui.text_edit_singleline(&mut self.new_custom_name);
        });
        ui.horizontal(|ui| {
            ui.label("Path");
            ui.text_edit_singleline(&mut self.new_custom_path);
            if ui.button("Browse").clicked() {
                self.file_picker.open_at_default();
            }
            if ui.button("Add custom").clicked() {
                self.add_custom_config();
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt(CUSTOM_CONFIGS_SCROLL_ID)
            .show(ui, |ui| {
                let mut remove = None;
                for (index, config) in self.gui_config.custom_vpn_configs.iter().enumerate() {
                    ui.group(|ui| {
                        ui.label(format!("{} ({})", config.name, config.protocol));
                        detail_label(ui, config.path.display().to_string());
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Remove").clicked() {
                                remove = Some(index);
                            }
                        });
                    });
                }
                if let Some(index) = remove {
                    self.gui_config.custom_vpn_configs.remove(index);
                    self.save_gui_config();
                }
            });
    }

    fn applications_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Applications");
        ui.horizontal(|ui| {
            ui.label("Name");
            ui.text_edit_singleline(&mut self.new_app_name);
        });
        ui.horizontal(|ui| {
            ui.label("Command");
            ui.text_edit_singleline(&mut self.new_app_command);
        });
        ui.horizontal(|ui| {
            ui.label("Args");
            ui.text_edit_singleline(&mut self.new_app_args);
            if ui.button("Add manual").clicked() {
                self.add_manual_app();
            }
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.heading("Added");
            if ui.button("Rescan desktop apps").clicked() {
                self.desktop_apps = scan_desktop_applications();
            }
        });
        egui::ScrollArea::vertical()
            .id_salt(ADDED_APPS_SCROLL_ID)
            .max_height(180.0)
            .show(ui, |ui| {
                let mut remove = None;
                for (index, app) in self.gui_config.applications.iter().enumerate() {
                    ui.group(|ui| {
                        ui.label(format!("{} [{}]", app.name, app.usage_count));
                        detail_label(ui, app.command_line());
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Remove").clicked() {
                                remove = Some(index);
                            }
                        });
                    });
                }
                if let Some(index) = remove {
                    self.gui_config.applications.remove(index);
                    self.save_gui_config();
                }
            });
        ui.separator();
        ui.heading("Discovered");
        egui::ScrollArea::vertical()
            .id_salt(DISCOVERED_APPS_SCROLL_ID)
            .show(ui, |ui| {
                let mut add = None;
                for (index, app) in self.desktop_apps.iter().take(200).enumerate() {
                    ui.group(|ui| {
                        ui.label(&app.name);
                        detail_label(ui, &app.command);
                        detail_label(ui, app.source.display().to_string());
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Add").clicked() {
                                add = Some(index);
                            }
                        });
                    });
                }
                if let Some(index) = add {
                    self.add_desktop_app(index);
                }
            });
    }

    fn status_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Status");
        if let Some(error) = &self.status.error {
            ui.colored_label(egui::Color32::from_rgb(220, 64, 64), error);
        }
        if self.status.namespaces.is_empty() {
            ui.label("No active vopono namespaces.");
            return;
        }
        for ns in &self.status.namespaces {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.heading(&ns.name);
                    ui.label(format!("{} {}", ns.provider, ns.protocol));
                    ui.label(format!("uptime {}", ns.uptime));
                });
                if ns.applications.is_empty() {
                    ui.label("Keep-alive or no lockfile applications.");
                } else {
                    for app in &ns.applications {
                        ui.horizontal(|ui| {
                            detail_label(ui, &app.command);
                            ui.small(format!("uptime {}", app.uptime));
                        });
                    }
                }
            });
        }
    }

    fn file_picker_window(&mut self, ctx: &egui::Context) -> Option<PathBuf> {
        if !self.file_picker.open {
            return None;
        }

        let mut chosen = None;
        let mut open = self.file_picker.open;
        egui::Window::new("Choose custom VPN config")
            .id(egui::Id::new("custom_config_file_picker"))
            .open(&mut open)
            .default_width(720.0)
            .default_height(520.0)
            .show(ctx, |ui| {
                ui.label(self.file_picker.current_dir.display().to_string());
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Home").clicked() {
                        self.file_picker.go_home();
                    }
                    if ui.button("Up").clicked() {
                        self.file_picker.go_up();
                    }
                    if ui.button("Cancel").clicked() {
                        self.file_picker.open = false;
                    }
                    ui.label(
                        "D-pad/arrow keys move, South/Enter opens or selects, East/Esc cancels.",
                    );
                });
                if let Some(error) = &self.file_picker.error {
                    ui.colored_label(egui::Color32::from_rgb(220, 64, 64), error);
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt(FILE_PICKER_SCROLL_ID)
                    .max_height(360.0)
                    .show(ui, |ui| {
                        let entries = self.file_picker.entries.clone();
                        for (index, entry) in entries.iter().enumerate() {
                            let selected = self.file_picker.selected == index;
                            let label = if entry.is_dir {
                                format!("{}/", entry.name)
                            } else {
                                entry.name.clone()
                            };
                            if ui.selectable_label(selected, label).clicked() {
                                self.file_picker.selected = index;
                            }
                            detail_label(ui, entry.path.display().to_string());
                            if selected
                                && ui
                                    .button(if entry.is_dir { "Open" } else { "Choose" })
                                    .clicked()
                            {
                                chosen = self.file_picker.activate_selected();
                            }
                            ui.separator();
                        }
                    });
            });

        self.file_picker.open = open && self.file_picker.open;
        chosen
    }
}

// TODO: Move each screen to its own file, separate out UI from actual actions (separate modules)
fn provider_config_state(provider: &VpnProvider) -> String {
    let mut states = Vec::new();
    if let Ok(openvpn) = provider.get_dyn_openvpn_provider() {
        states.push(format!(
            "OpenVPN {}",
            if openvpn.openvpn_dir().is_ok_and(|dir| has_files(&dir)) {
                "configured"
            } else {
                "missing"
            }
        ));
    }
    if let Ok(wireguard) = provider.get_dyn_wireguard_provider() {
        states.push(format!(
            "WireGuard {}",
            if wireguard.wireguard_dir().is_ok_and(|dir| has_files(&dir)) {
                "configured"
            } else {
                "missing"
            }
        ));
    }
    if states.is_empty() {
        "no syncable protocols".to_string()
    } else {
        states.join(" / ")
    }
}

#[derive(Clone)]
struct SyncedVpnConfig {
    provider: VpnProvider,
    protocol: Protocol,
    server: String,
    path: PathBuf,
}

#[derive(Clone)]
enum VpnChoice {
    Synced(SyncedVpnConfig),
    Custom {
        index: usize,
        config: CustomVpnConfig,
    },
}

impl VpnChoice {
    fn primary_label(&self) -> String {
        match self {
            Self::Synced(config) => {
                format!("{} {} {}", config.provider, config.protocol, config.server)
            }
            Self::Custom { config, .. } => {
                format!("{} ({})", config.name, config.protocol)
            }
        }
    }

    fn detail_label(&self) -> String {
        match self {
            Self::Synced(config) => config.path.display().to_string(),
            Self::Custom { config, .. } => config.path.display().to_string(),
        }
    }
}

fn launch_vpn_choice(
    choice: &VpnChoice,
    app: &ApplicationProfile,
    launch: &LaunchConfig,
) -> anyhow::Result<String> {
    match choice {
        VpnChoice::Synced(config) => launcher::launch_provider_config(
            config.provider.clone(),
            config.protocol.clone(),
            &config.server,
            app,
            launch,
        ),
        VpnChoice::Custom { config, .. } => launcher::launch_custom_config(config, app, launch),
    }
}

fn vpn_choices_from_configs(
    custom_configs: &[CustomVpnConfig],
    synced_configs: &[SyncedVpnConfig],
) -> Vec<VpnChoice> {
    custom_configs
        .iter()
        .enumerate()
        .map(|(index, config)| VpnChoice::Custom {
            index,
            config: config.clone(),
        })
        .chain(synced_configs.iter().cloned().map(VpnChoice::Synced))
        .collect()
}

fn scan_synced_configs() -> Vec<SyncedVpnConfig> {
    let mut configs = Vec::new();

    for provider in VpnProvider::iter().filter(|provider| {
        !matches!(
            provider,
            VpnProvider::Custom | VpnProvider::None | VpnProvider::Warp
        )
    }) {
        if let Ok(openvpn) = provider.get_dyn_openvpn_provider()
            && let Ok(dir) = openvpn.openvpn_dir()
        {
            configs.extend(provider_configs_from_dir(
                &provider,
                Protocol::OpenVpn,
                &dir,
            ));
        }
        if let Ok(wireguard) = provider.get_dyn_wireguard_provider()
            && let Ok(dir) = wireguard.wireguard_dir()
        {
            configs.extend(provider_configs_from_dir(
                &provider,
                Protocol::Wireguard,
                &dir,
            ));
        }
    }

    configs.sort_by(|a, b| {
        a.provider
            .to_string()
            .cmp(&b.provider.to_string())
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
            .then_with(|| a.server.cmp(&b.server))
    });
    configs
}

fn provider_configs_from_dir(
    provider: &VpnProvider,
    protocol: Protocol,
    dir: &Path,
) -> Vec<SyncedVpnConfig> {
    if !dir.exists() {
        return Vec::new();
    }

    get_configs_from_alias(dir, "")
        .into_iter()
        .filter_map(|path| {
            let server = path.file_name()?.to_str()?.to_string();
            Some(SyncedVpnConfig {
                provider: provider.clone(),
                protocol: protocol.clone(),
                server,
                path,
            })
        })
        .collect()
}

#[derive(Clone)]
struct FilePickerEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
}

struct FilePicker {
    open: bool,
    current_dir: PathBuf,
    entries: Vec<FilePickerEntry>,
    selected: usize,
    error: Option<String>,
}

impl FilePicker {
    fn new() -> Self {
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

    fn open_at_default(&mut self) {
        if !self.current_dir.exists() {
            self.current_dir = default_picker_dir();
        }
        self.open = true;
        self.refresh();
    }

    fn go_home(&mut self) {
        self.current_dir = default_picker_dir();
        self.refresh();
    }

    fn go_up(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.current_dir = parent.to_path_buf();
            self.refresh();
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let current = self.selected as isize;
        let len = self.entries.len() as isize;
        self.selected = (current + delta).rem_euclid(len) as usize;
    }

    fn activate_selected(&mut self) -> Option<PathBuf> {
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

fn has_files(path: &std::path::Path) -> bool {
    path.read_dir()
        .is_ok_and(|mut entries| entries.any(|entry| entry.is_ok()))
}

fn accepts_gamepad(ctx: &egui::Context) -> bool {
    ctx.input(|input| {
        let viewport = input.viewport();
        viewport.focused.unwrap_or(true) && !viewport.minimized.unwrap_or(false)
    })
}

// TODO: Move these utils to a utils module not all in one giant file
fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    text.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u16>()
                .map_err(|_| format!("Invalid port '{part}'"))
        })
        .collect()
}

fn detail_label(ui: &mut egui::Ui, text: impl AsRef<str>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
    fn file_picker_accepts_only_vpn_config_extensions() {
        assert!(is_vpn_config_file(Path::new("airvpn.conf")));
        assert!(is_vpn_config_file(Path::new("airvpn.ovpn")));
        assert!(!is_vpn_config_file(Path::new("airvpn.txt")));
    }

    #[test]
    fn synced_config_server_uses_filename_with_extension() {
        let path = PathBuf::from("/tmp/se-stockholm.conf");
        let configs = provider_configs_from_paths(
            &VpnProvider::Mullvad,
            Protocol::Wireguard,
            vec![path.clone()],
        );
        assert_eq!(configs[0].server, "se-stockholm.conf");
        assert_eq!(configs[0].path, path);
    }

    #[test]
    fn launch_vpn_choices_put_custom_configs_first() {
        let custom = CustomVpnConfig {
            name: "AirVPN custom".to_string(),
            path: PathBuf::from("/tmp/airvpn.conf"),
            protocol: "wireguard".to_string(),
            usage_count: 0,
        };
        let synced = SyncedVpnConfig {
            provider: VpnProvider::Mullvad,
            protocol: Protocol::Wireguard,
            server: "se-stockholm.conf".to_string(),
            path: PathBuf::from("/tmp/se-stockholm.conf"),
        };

        let choices = vpn_choices_from_configs(&[custom], &[synced]);
        assert!(matches!(choices[0], VpnChoice::Custom { .. }));
        assert!(matches!(choices[1], VpnChoice::Synced(_)));
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

    fn provider_configs_from_paths(
        provider: &VpnProvider,
        protocol: Protocol,
        paths: Vec<PathBuf>,
    ) -> Vec<SyncedVpnConfig> {
        paths
            .into_iter()
            .filter_map(|path| {
                let server = path.file_name()?.to_str()?.to_string();
                Some(SyncedVpnConfig {
                    provider: provider.clone(),
                    protocol: protocol.clone(),
                    server,
                    path,
                })
            })
            .collect()
    }
}
