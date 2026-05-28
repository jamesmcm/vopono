mod applications;
mod config;
mod launch;
mod providers;
mod status;

use super::utils::FILE_PICKER_SCROLL_ID;
use super::{View, VoponoGuiApp};
use eframe::egui;
use std::path::PathBuf;

impl VoponoGuiApp {
    pub(super) fn main_ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
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
                if ui.button("Exit").clicked() {
                    self.should_quit = true;
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
                            super::utils::detail_label(ui, entry.path.display().to_string());
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
