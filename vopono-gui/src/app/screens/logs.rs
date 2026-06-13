use super::super::VoponoGuiApp;
use eframe::egui;

impl VoponoGuiApp {
    pub(super) fn logs_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Logs");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Clear finished").clicked() {
                self.logs.retain(|log| log.running);
            }
            if ui.button("Clear all").clicked() {
                self.logs.clear();
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.logs.is_empty() {
                ui.label("No launches logged yet.");
            }
            for log in self.logs.iter().rev() {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(if log.running { "Running" } else { "Finished" });
                        ui.label(&log.title);
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt(("launch_log", log.id))
                        .max_height(260.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &log.lines {
                                ui.monospace(line);
                            }
                        });
                });
                ui.separator();
            }
        });
    }
}
