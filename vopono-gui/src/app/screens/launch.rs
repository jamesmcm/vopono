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
}
