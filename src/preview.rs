//! Inspection and thumbnails: page counts, encryption state and small PNG renders of
//! each page, used by the GUI to show previews and drive the page picker.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat};

use crate::images;
use crate::merge::{self, InputKind, MergeError, MergeInput};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Thumbs {
    None,
    First,
    /// Render every page up to this many.
    All(usize),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Inspection {
    pub kind: &'static str,
    pub pages: u32,
    pub encrypted: bool,
    /// Page sizes in points (width, height) for the pages that were rendered or counted.
    pub page_sizes: Vec<(f32, f32)>,
    /// PNG thumbnails as `data:` URLs, in page order (may be shorter than `pages`).
    pub thumbs: Vec<String>,
}

/// Inspect a file. `password` is used for encrypted PDFs; a wrong or missing one surfaces
/// as [`MergeError::Encrypted`] / [`MergeError::WrongPassword`].
pub fn inspect(
    name: &str,
    data: &[u8],
    password: Option<&str>,
    thumbs: Thumbs,
    max_edge_px: u32,
) -> Result<Inspection, MergeError> {
    let kind = merge::detect_kind(name, data).ok_or_else(|| MergeError::Unsupported {
        name: name.to_string(),
    })?;
    match kind {
        InputKind::Pdf => inspect_pdf(name, data, password, thumbs, max_edge_px),
        InputKind::Image => inspect_image(name, data, thumbs, max_edge_px),
    }
}

fn inspect_pdf(
    name: &str,
    data: &[u8],
    password: Option<&str>,
    thumbs: Thumbs,
    max_edge_px: u32,
) -> Result<Inspection, MergeError> {
    let input = MergeInput {
        name: name.to_string(),
        data: data.to_vec(),
        password: password.map(|p| p.to_string()),
        ..MergeInput::default()
    };
    let (mut doc, was_encrypted) = merge::load_pdf(&input)?;
    let pages = doc.get_pages();
    let count = pages.len() as u32;

    // hayro cannot open encrypted files; hand it the decrypted bytes lopdf produced.
    let render_bytes: Vec<u8> = if was_encrypted {
        let mut buf = Vec::new();
        doc.save_to(&mut buf).map_err(MergeError::Write)?;
        buf
    } else {
        data.to_vec()
    };

    let mut page_sizes = Vec::new();
    for (_, id) in pages.iter().take(match thumbs {
        Thumbs::None | Thumbs::First => 1,
        Thumbs::All(n) => n,
    }) {
        page_sizes.push(merge::page_size_pt(&doc, *id));
    }

    let wanted = match thumbs {
        Thumbs::None => 0,
        Thumbs::First => 1,
        Thumbs::All(n) => n,
    };
    let mut out = Vec::new();
    if wanted > 0 {
        out = render_pdf_thumbs(render_bytes, wanted, max_edge_px);
    }
    Ok(Inspection {
        kind: "pdf",
        pages: count,
        encrypted: was_encrypted,
        page_sizes,
        thumbs: out,
    })
}

/// Render up to `wanted` pages to PNG data URLs. Rendering problems yield fewer thumbnails,
/// never an error: a preview is a convenience, the merge itself does not depend on it.
fn render_pdf_thumbs(bytes: Vec<u8>, wanted: usize, max_edge_px: u32) -> Vec<String> {
    use hayro::hayro_interpret::InterpreterSettings;
    use hayro::hayro_syntax::Pdf;
    use hayro::vello_cpu::color::palette::css::WHITE;
    use hayro::{render, RenderCache, RenderSettings};

    let Ok(pdf) = Pdf::new(bytes) else {
        return Vec::new();
    };
    let settings = InterpreterSettings::default();
    let cache = RenderCache::new();
    let mut out = Vec::new();
    for page in pdf.pages().iter().take(wanted) {
        let (w, h) = page.render_dimensions();
        let scale = (max_edge_px as f32 / w.max(h).max(1.0)).min(4.0);
        let pixmap = render(
            page,
            &cache,
            &settings,
            &RenderSettings {
                x_scale: scale,
                y_scale: scale,
                bg_color: WHITE,
                ..Default::default()
            },
        );
        let (pw, ph) = (pixmap.width() as u32, pixmap.height() as u32);
        let rgba = pixmap.take_unpremultiplied();
        let mut rgb = Vec::with_capacity((pw * ph * 3) as usize);
        for px in rgba {
            let a = px.a as u32;
            rgb.push(((px.r as u32 * a + 255 * (255 - a)) / 255) as u8);
            rgb.push(((px.g as u32 * a + 255 * (255 - a)) / 255) as u8);
            rgb.push(((px.b as u32 * a + 255 * (255 - a)) / 255) as u8);
        }
        let Some(img) = image::RgbImage::from_raw(pw, ph, rgb) else {
            break;
        };
        match png_data_url(&DynamicImage::ImageRgb8(img)) {
            Some(url) => out.push(url),
            None => break,
        }
    }
    out
}

fn inspect_image(
    name: &str,
    data: &[u8],
    thumbs: Thumbs,
    max_edge_px: u32,
) -> Result<Inspection, MergeError> {
    let pages = images::decode_pages(name, data).map_err(|e| MergeError::Image {
        name: name.to_string(),
        message: e.0,
    })?;
    let count = pages.len() as u32;
    let wanted = match thumbs {
        Thumbs::None => 0,
        Thumbs::First => 1,
        Thumbs::All(n) => n,
    };
    let mut page_sizes = Vec::new();
    let mut out = Vec::new();
    for page in pages.iter().take(wanted.max(1)) {
        let dpi = page
            .dpi
            .filter(|(x, y)| (30.0..=2400.0).contains(x) && (30.0..=2400.0).contains(y));
        let (dx, dy) = dpi.unwrap_or((72.0, 72.0));
        page_sizes.push((
            (page.width as f64 * 72.0 / dx) as f32,
            (page.height as f64 * 72.0 / dy) as f32,
        ));
        if out.len() < wanted {
            if let Ok(img) = images::to_dynamic(page) {
                let thumb = img.thumbnail(max_edge_px, max_edge_px);
                if let Some(url) = png_data_url(&thumb) {
                    out.push(url);
                }
            }
        }
    }
    Ok(Inspection {
        kind: "image",
        pages: count,
        encrypted: false,
        page_sizes,
        thumbs: out,
    })
}

fn png_data_url(img: &DynamicImage) -> Option<String> {
    let mut buf = Cursor::new(Vec::new());
    img.write_to(&mut buf, ImageFormat::Png).ok()?;
    Some(format!(
        "data:image/png;base64,{}",
        base64(&buf.into_inner())
    ))
}

/// Minimal standard base64 encoder (no padding quirks, no dependency).
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn inspects_pdf_with_thumbnails() {
        let pdf = crate::merge::tests::sample_pdf(3, "Hello");
        let info = inspect("x.pdf", &pdf, None, Thumbs::All(10), 64).unwrap();
        assert_eq!(info.kind, "pdf");
        assert_eq!(info.pages, 3);
        assert!(!info.encrypted);
        assert_eq!(info.thumbs.len(), 3, "hayro should render all three pages");
        assert!(info.thumbs[0].starts_with("data:image/png;base64,"));
        assert_eq!(info.page_sizes.len(), 3);
        assert!((info.page_sizes[0].0 - 612.0).abs() < 1.0);
    }

    #[test]
    fn inspects_encrypted_pdf_after_decrypting() {
        let locked = include_bytes!("../tests/fixtures/owner_locked.pdf");
        let info = inspect("locked.pdf", locked, None, Thumbs::First, 48).unwrap();
        assert!(info.encrypted);
        assert_eq!(info.pages, 2);
        assert_eq!(info.thumbs.len(), 1);
        let user = include_bytes!("../tests/fixtures/user_locked.pdf");
        assert!(matches!(
            inspect("u.pdf", user, None, Thumbs::None, 48),
            Err(MergeError::Encrypted { .. })
        ));
        assert!(matches!(
            inspect("u.pdf", user, Some("nope"), Thumbs::None, 48),
            Err(MergeError::WrongPassword { .. })
        ));
    }

    #[test]
    fn inspects_image() {
        let png = crate::merge::tests::sample_png(30, 10);
        let info = inspect("i.png", &png, None, Thumbs::First, 16).unwrap();
        assert_eq!(info.kind, "image");
        assert_eq!(info.pages, 1);
        assert_eq!(info.thumbs.len(), 1);
        assert_eq!(info.page_sizes[0], (30.0, 10.0));
    }
}
