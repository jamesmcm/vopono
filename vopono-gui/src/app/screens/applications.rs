use super::super::VoponoGuiApp;
use super::super::utils::{ADDED_APPS_SCROLL_ID, DISCOVERED_APPS_SCROLL_ID, detail_label};
use crate::desktop::scan_desktop_applications;
use eframe::egui;

impl VoponoGuiApp {
    pub(super) fn applications_view(&mut self, ui: &mut egui::Ui) {
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
        });
        ui.horizontal(|ui| {
            ui.label("Env");
            ui.text_edit_singleline(&mut self.new_app_env_vars);
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
                let mut save_env = None;
                for (index, app) in self.gui_config.applications.iter().enumerate() {
                    ui.group(|ui| {
                        ui.label(format!("{} [{}]", app.name, app.usage_count));
                        detail_label(ui, app.command_line());
                        let env_line = self
                            .app_env_edit_text
                            .entry(app.command.clone())
                            .or_insert_with(|| app.env_line());
                        ui.horizontal(|ui| {
                            ui.label("Env");
                            ui.text_edit_singleline(env_line);
                            if ui.button("Save env").clicked() {
                                save_env = Some((index, env_line.clone()));
                            }
                        });
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Remove").clicked() {
                                remove = Some(index);
                            }
                        });
                    });
                }
                if let Some((index, env_line)) = save_env {
                    match super::super::parse_env_vars(&env_line) {
                        Ok(env_vars) => {
                            if let Some(app) = self.gui_config.applications.get_mut(index) {
                                app.env_vars = super::super::merge_env_vars(
                                    crate::desktop::env_vars_for_command(&app.command),
                                    env_vars,
                                );
                                self.save_gui_config();
                            }
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                if let Some(index) = remove {
                    let app = self.gui_config.applications.remove(index);
                    self.app_env_edit_text.remove(&app.command);
                    self.select_default_launch_targets();
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
}
