mod app;
mod brand;
mod desktop;
mod gui_config;
mod launcher;
mod status;
mod tray;

use app::VoponoGuiApp;
use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

fn main() -> eframe::Result<()> {
    detach_from_terminal_if_needed();
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

fn detach_from_terminal_if_needed() {
    if std::env::var_os("VOPONO_GUI_FOREGROUND").is_some()
        || std::env::var_os("VOPONO_GUI_DETACHED").is_some()
        || !std::io::stdout().is_terminal()
    {
        return;
    }

    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut command = Command::new(exe);
    command
        .args(std::env::args_os().skip(1))
        .env("VOPONO_GUI_DETACHED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Ok(current_dir) = std::env::current_dir() {
        command.current_dir(current_dir);
    }

    command.process_group(0);

    if command.spawn().is_ok() {
        std::process::exit(0);
    }
}
