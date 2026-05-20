// TODO: Fix this - use transparent background and remove text from logo
// TODO: Is there a better way of bundling than cramming the bytes in the binary like this? This is
// okay for now
const LOGO_BYTES: &[u8] = include_bytes!("../../logos/voponologo.png");

pub fn window_icon() -> anyhow::Result<egui::IconData> {
    let image = logo_rgba_exact(64, 64, None)?;
    Ok(egui::IconData {
        rgba: image.rgba,
        width: image.width,
        height: image.height,
    })
}

pub fn logo_texture_image() -> anyhow::Result<egui::ColorImage> {
    let image = logo_rgba_exact(96, 96, None)?;
    Ok(egui::ColorImage::from_rgba_unmultiplied(
        [image.width as usize, image.height as usize],
        &image.rgba,
    ))
}

pub fn tray_icon(active: bool) -> anyhow::Result<tray_icon::Icon> {
    let image = logo_rgba_exact(32, 32, Some(active))?;
    tray_icon::Icon::from_rgba(image.rgba, image.width, image.height)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[derive(Debug, Clone)]
struct LogoRgba {
    rgba: Vec<u8>,
    width: u32,
    height: u32,
}

fn logo_rgba_exact(width: u32, height: u32, status_dot: Option<bool>) -> anyhow::Result<LogoRgba> {
    let mut image = image::load_from_memory(LOGO_BYTES)?
        .resize_exact(width, height, image::imageops::FilterType::Lanczos3)
        .to_rgba8();

    if let Some(active) = status_dot {
        draw_status_dot(&mut image, active);
    }

    Ok(LogoRgba {
        rgba: image.into_raw(),
        width,
        height,
    })
}

fn draw_status_dot(image: &mut image::RgbaImage, active: bool) {
    let (width, height) = image.dimensions();
    let radius = (width.min(height) / 6).max(3) as i32;
    let center_x = width as i32 - radius - 2;
    let center_y = height as i32 - radius - 2;
    let fill = if active {
        image::Rgba([31, 153, 88, 255])
    } else {
        image::Rgba([120, 124, 130, 255])
    };
    let border = image::Rgba([255, 255, 255, 235]);

    for y in 0..height as i32 {
        for x in 0..width as i32 {
            let dx = x - center_x;
            let dy = y - center_y;
            let distance_sq = dx * dx + dy * dy;
            if distance_sq <= (radius + 1) * (radius + 1) {
                image.put_pixel(x as u32, y as u32, border);
            }
            if distance_sq <= radius * radius {
                image.put_pixel(x as u32, y as u32, fill);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_assets_decode_for_window_and_tray() {
        let window = window_icon().expect("window icon decodes");
        assert_eq!((window.width, window.height), (64, 64));
        assert_eq!(window.rgba.len(), 64 * 64 * 4);

        tray_icon(true).expect("active tray icon decodes");
        tray_icon(false).expect("idle tray icon decodes");
    }
}
