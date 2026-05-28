use crate::status::StatusSnapshot;
use std::panic::{AssertUnwindSafe, catch_unwind};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};

const MENU_SHOW: &str = "vopono-gui-show";
const MENU_HIDE: &str = "vopono-gui-hide";
const MENU_QUIT: &str = "vopono-gui-quit";

pub enum TrayCommand {
    Show,
    Hide,
    Quit,
}

pub struct TrayManager {
    tray: Option<TrayIcon>,
    status_item: Option<MenuItem>,
    active: bool,
    last_error: Option<String>,
    icon_active: Option<Icon>,
    icon_idle: Option<Icon>,
}

impl TrayManager {
    pub fn new(snapshot: &StatusSnapshot) -> Self {
        let icon_active = crate::brand::tray_icon(true).ok();
        let icon_idle = crate::brand::tray_icon(false).ok();
        let mut manager = Self {
            tray: None,
            status_item: None,
            active: false,
            last_error: None,
            icon_active,
            icon_idle,
        };
        manager.try_create(snapshot);
        manager
    }

    pub fn update_status(&mut self, snapshot: &StatusSnapshot) {
        let active = snapshot.active_count() > 0;
        let text = snapshot.tray_text();

        if let Some(item) = &self.status_item {
            item.set_text(text.replace('\n', " | "));
        }

        if self.active != active {
            if let Some(tray) = &self.tray
                && let Err(error) = tray.set_icon(self.cached_icon(active))
            {
                self.last_error = Some(error.to_string());
            }
            self.active = active;
        }

        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(text.as_str()));
            tray.set_title(Some(if active {
                "vopono active"
            } else {
                "vopono idle"
            }));
        }
    }

    pub fn poll_command(&mut self) -> Option<TrayCommand> {
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == MENU_SHOW {
                return Some(TrayCommand::Show);
            }
            if event.id == MENU_HIDE {
                return Some(TrayCommand::Hide);
            }
            if event.id == MENU_QUIT {
                return Some(TrayCommand::Quit);
            }
        }
        None
    }

    pub fn error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn pump_events(&self) {
        pump_platform_events();
    }

    fn try_create(&mut self, snapshot: &StatusSnapshot) {
        if std::env::var_os("VOPONO_GUI_DISABLE_TRAY").is_some() {
            self.last_error = Some("Tray icon disabled by VOPONO_GUI_DISABLE_TRAY".to_string());
            return;
        }

        let result = catch_unwind(AssertUnwindSafe(|| self.try_create_inner(snapshot)));
        match result {
            Ok(Ok((tray, status))) => {
                self.tray = Some(tray);
                self.status_item = Some(status);
                self.active = snapshot.active_count() > 0;
            }
            Ok(Err(error)) => {
                self.last_error = Some(error.to_string());
            }
            Err(_) => {
                self.last_error = Some(
                    "Tray backend panicked during setup; continuing without tray icon".to_string(),
                );
            }
        }
    }

    fn try_create_inner(&self, snapshot: &StatusSnapshot) -> anyhow::Result<(TrayIcon, MenuItem)> {
        ensure_platform_tray_ready()?;

        let menu = Menu::new();
        let status = MenuItem::with_id("vopono-gui-status", snapshot.tray_text(), false, None);
        let show = MenuItem::with_id(MENU_SHOW, "Show vopono-gui", true, None);
        let hide = MenuItem::with_id(MENU_HIDE, "Hide window", true, None);
        let quit = MenuItem::with_id(MENU_QUIT, "Quit", true, None);

        menu.append(&status)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        menu.append(&show)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        menu.append(&hide)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        menu.append(&quit)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(snapshot.tray_text())
            .with_icon(
                self.cached_icon(snapshot.active_count() > 0)
                    .ok_or_else(|| anyhow::anyhow!("Tray icon asset could not be decoded"))?,
            )
            .build()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        Ok((tray, status))
    }

    fn cached_icon(&self, active: bool) -> Option<Icon> {
        if active {
            self.icon_active.clone()
        } else {
            self.icon_idle.clone()
        }
    }
}

#[cfg(test)]
fn ensure_platform_tray_ready() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "Tray creation is skipped in tests to avoid starting a GTK/AppIndicator session"
    ))
}

#[cfg(not(test))]
fn ensure_platform_tray_ready() -> anyhow::Result<()> {
    if gtk::is_initialized_main_thread() {
        return Ok(());
    }

    gtk::init().map_err(|error| {
        anyhow::anyhow!(
            "GTK could not be initialized for tray icon support: {}",
            error
        )
    })
}

#[cfg(not(test))]
fn pump_platform_events() {
    if gtk::is_initialized_main_thread() {
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
    }
}

#[cfg(test)]
fn pump_platform_events() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_manager_new_never_panics_when_tray_backend_is_unavailable() {
        let result = catch_unwind(|| TrayManager::new(&StatusSnapshot::default()));
        assert!(result.is_ok());
    }

    #[test]
    fn tray_manager_reports_setup_error_instead_of_panicking() {
        let manager = TrayManager::new(&StatusSnapshot::default());
        if manager.tray.is_none() {
            assert!(manager.error().is_some());
        }
    }
}
