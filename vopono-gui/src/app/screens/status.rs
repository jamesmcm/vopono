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
            ui.push_id(&ns.name, |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.heading(&ns.name);
                        ui.label(format!("{} {}", ns.provider, ns.protocol));
                        ui.label(format!("uptime {}", ns.uptime));
                    });
                    if let Some(health) = &ns.health {
                        let state = match health.state {
                            vopono_core::network::health::State::Connected => "connected",
                            vopono_core::network::health::State::Degraded => "degraded",
                            vopono_core::network::health::State::Reconnecting => "reconnecting",
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let sample_age = now.saturating_sub(health.checked_at);
                        ui.label(format!(
                            "TCP/DNS health: {state} (checked {sample_age}s ago) · recovery attempts: {}",
                            health.reconnect_attempts
                        ));
                        if let Some(age) = health.handshake_age_seconds {
                            ui.small(format!("WireGuard handshake: {age}s ago"));
                        }
                        if let Some(error) = &health.last_error {
                            ui.label(error);
                        }
                        if !health.diagnostics.is_empty() {
                            ui.collapsing("Diagnostic evidence", |ui| {
                                for diagnostic in &health.diagnostics {
                                    let dstate = match diagnostic.state {
                                        vopono_core::diagnostics::DiagnosticState::Pass => "PASS",
                                        vopono_core::diagnostics::DiagnosticState::Warning => {
                                            "WARN"
                                        }
                                        vopono_core::diagnostics::DiagnosticState::Fail => "FAIL",
                                        vopono_core::diagnostics::DiagnosticState::Skipped => {
                                            "SKIP"
                                        }
                                    };
                                    let dcode = format_diagnostic_code(diagnostic.code);
                                    ui.label(format!(
                                        "[{dstate}] {dcode}: {}",
                                        diagnostic.message
                                    ));
                                    if let Some(action) = &diagnostic.action {
                                        ui.small(action);
                                    }
                                }
                            });
                        }
                    } else {
                        ui.small("Health monitoring is disabled for this namespace.");
                    }
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
            });
        }
    }
}

fn format_diagnostic_code(code: vopono_core::diagnostics::DiagnosticCode) -> String {
    let raw = format!("{code:?}");
    let mut out = String::with_capacity(raw.len() + 4);
    for (idx, ch) in raw.chars().enumerate() {
        if idx > 0 && ch.is_uppercase() {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}
