use super::super::VoponoGuiApp;
use crate::gui_config::{load_vopono_config_text, save_vopono_config_text};
use eframe::egui;

impl VoponoGuiApp {
    pub(super) fn config_view(&mut self, ui: &mut egui::Ui) {
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
}
