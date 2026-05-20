use super::{View, VoponoGuiApp};
use eframe::egui;
use gilrs::{Button, EventType};

enum GamepadAction {
    Down,
    Up,
    Launch,
    Cancel,
    Refresh,
}

impl VoponoGuiApp {
    pub(super) fn handle_shortcuts(&mut self, ctx: &egui::Context) {
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

    pub(super) fn handle_gamepad(&mut self, ctx: &egui::Context) {
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
}

fn accepts_gamepad(ctx: &egui::Context) -> bool {
    ctx.input(|input| {
        let viewport = input.viewport();
        viewport.focused.unwrap_or(true) && !viewport.minimized.unwrap_or(false)
    })
}
