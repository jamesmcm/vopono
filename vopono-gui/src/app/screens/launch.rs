use super::super::VoponoGuiApp;
use super::super::utils::{LAUNCH_APPS_SCROLL_ID, LAUNCH_CUSTOM_SCROLL_ID, detail_label};
use eframe::egui;

impl VoponoGuiApp {
    pub(super) fn launch_view(&mut self, ui: &mut egui::Ui) {
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
                        for choice in &vpn_choices {
                            let key = choice.key();
                            let selected = self.selected_vpn_key.as_ref() == Some(&key);
                            if ui
                                .selectable_label(
                                    selected,
                                    format!(
                                        "{} [{}]",
                                        choice.primary_label(),
                                        self.vpn_usage_count(choice)
                                    ),
                                )
                                .clicked()
                            {
                                self.selected_vpn_key = Some(key);
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
                        for app in &self.gui_config.applications {
                            let selected = self.selected_app_cmd.as_ref() == Some(&app.command);
                            if ui
                                .selectable_label(
                                    selected,
                                    format!("{} [{}]", app.name, app.usage_count),
                                )
                                .clicked()
                            {
                                self.selected_app_cmd = Some(app.command.clone());
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
        if self.gui_config.launch.port_forwarding {
            match &self.provider_forwarded_port {
                Some(status) => {
                    let age = status
                        .age()
                        .map(format_forwarded_port_age)
                        .unwrap_or_else(|| "unknown age".to_string());
                    detail_label(
                        ui,
                        format!("Latest provider forwarded port: {} ({age})", status.port),
                    );
                }
                None => {
                    detail_label(
                        ui,
                        "Provider forwarded port will appear here after a callback-capable provider reports it.",
                    );
                }
            }
        }
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
}

fn format_forwarded_port_age(age: std::time::Duration) -> String {
    let seconds = age.as_secs();
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3_600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3_600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}
