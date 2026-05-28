use super::super::VoponoGuiApp;
use super::super::utils::detail_label;
use eframe::egui;

impl VoponoGuiApp {
    pub(super) fn status_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Status");
        for error in &self.status.errors {
            ui.colored_label(egui::Color32::from_rgb(220, 64, 64), error);
        }
        if self.status.namespaces.is_empty() {
            ui.label("No active vopono namespaces.");
            return;
        }
        if let Some(status) = &self.provider_forwarded_port {
            ui.label(format!("Latest provider forwarded port: {}", status.port));
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
}
