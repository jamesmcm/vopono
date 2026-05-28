use super::super::VoponoGuiApp;
use super::super::utils::{CUSTOM_CONFIGS_SCROLL_ID, PROVIDERS_SCROLL_ID, detail_label};
use super::super::vpn::provider_config_state;
use crate::launcher;
use eframe::egui;
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;

impl VoponoGuiApp {
    pub(super) fn providers_view(&mut self, ui: &mut egui::Ui) {
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
}
