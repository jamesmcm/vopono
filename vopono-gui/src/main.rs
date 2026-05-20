mod app;
mod brand;
mod desktop;
mod gui_config;
mod launcher;
mod status;
mod tray;

use app::VoponoGuiApp;

fn main() -> eframe::Result<()> {
    pretty_env_logger::init();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("vopono-gui")
        .with_inner_size([1100.0, 720.0])
        .with_min_inner_size([760.0, 520.0]);
    if let Ok(icon) = brand::window_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "vopono-gui",
        options,
        Box::new(|cc| Ok(Box::new(VoponoGuiApp::new(cc)))),
    )
}
