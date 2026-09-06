//! Image decoding for the merger: every supported raster/vector format becomes one or
//! more [`ImagePage`]s ready to be embedded as PDF image XObjects.
//!
//! * JPEG (RGB/Gray) is passed through untouched.
//! * TIFF is read page by page with the `tiff` crate (multi-page scans).
//! * SVG is rasterised with `resvg`.
//! * Everything else goes through the `image` crate.
//!
//! Physical resolution (DPI) is read from PNG `pHYs`, JPEG JFIF/EXIF, and TIFF tags so
//! that a 300 DPI scan becomes a letter-sized page instead of a poster.

use std::io::Cursor;

use image::{ColorType, DynamicImage, ImageDecoder, ImageFormat, ImageReader};

/// Pixel data ready for a PDF image XObject.
#[derive(Debug, Clone)]
pub enum Pixels {
    /// Raw JPEG file bytes, embedded with `DCTDecode`.
    Jpeg(Vec<u8>),
    /// 8-bit samples, 1 (gray) or 3 (RGB) per pixel, embedded with `FlateDecode`.
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct ImagePage {
    pub width: u32,
    pub height: u32,
    /// `DeviceGray` or `DeviceRGB`.
    pub color_space: &'static str,
    pub pixels: Pixels,
    /// Horizontal and vertical resolution in dots per inch, when the file declares one.
    pub dpi: Option<(f64, f64)>,
}

#[derive(Debug)]
pub struct ImageError(pub String);

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ImageError {}

impl From<image::ImageError> for ImageError {
    fn from(e: image::ImageError) -> Self {
        ImageError(e.to_string())
    }
}

/// True for SVG documents (checked by content, since SVG has no magic number).
pub fn looks_like_svg(name: &str, data: &[u8]) -> bool {
    let ext = name.rsplit('.').next().map(|e| e.to_ascii_lowercase());
    if matches!(ext.as_deref(), Some("svg") | Some("svgz")) {
        return true;
    }
    let head = &data[..data.len().min(512)];
    let text = String::from_utf8_lossy(head);
    text.contains("<svg")
}

/// Decode a file into pages. Most formats yield one page; TIFF may yield many.
pub fn decode_pages(name: &str, data: &[u8]) -> Result<Vec<ImagePage>, ImageError> {
    if looks_like_svg(name, data) {
        return Ok(vec![render_svg(data)?]);
    }
    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| ImageError(e.to_string()))?;
    let format = reader.format();
    if format == Some(ImageFormat::Tiff) {
        match decode_tiff_pages(data) {
            Ok(pages) if !pages.is_empty() => return Ok(pages),
            // Unusual TIFF flavour: fall back to the image crate for the first page.
            _ => {}
        }
    }
    let decoder = reader.into_decoder()?;
    let (width, height) = decoder.dimensions();
    let color = decoder.color_type();
    if format == Some(ImageFormat::Jpeg) && matches!(color, ColorType::Rgb8 | ColorType::L8) {
        return Ok(vec![ImagePage {
            width,
            height,
            color_space: if color == ColorType::Rgb8 {
                "DeviceRGB"
            } else {
                "DeviceGray"
            },
            pixels: Pixels::Jpeg(data.to_vec()),
            dpi: jpeg_dpi(data),
        }]);
    }
    let dpi = match format {
        Some(ImageFormat::Png) => png_dpi(data),
        Some(ImageFormat::Jpeg) => jpeg_dpi(data),
        _ => None,
    };
    let image = DynamicImage::from_decoder(decoder)?;
    Ok(vec![from_dynamic(&image, dpi)])
}

/// Convert any decoded image to 8-bit Gray or RGB samples, compositing alpha onto white.
pub fn from_dynamic(image: &DynamicImage, dpi: Option<(f64, f64)>) -> ImagePage {
    let color = image.color();
    let (samples, color_space) = if color.has_color() {
        if color.has_alpha() {
            let rgba = image.to_rgba8();
            let mut out = Vec::with_capacity((rgba.width() * rgba.height() * 3) as usize);
            for px in rgba.pixels() {
                let a = px[3] as u32;
                for &channel in &px.0[..3] {
                    out.push(((channel as u32 * a + 255 * (255 - a)) / 255) as u8);
                }
            }
            (out, "DeviceRGB")
        } else {
            (image.to_rgb8().into_raw(), "DeviceRGB")
        }
    } else if color.has_alpha() {
        let la = image.to_luma_alpha8();
        let out = la
            .pixels()
            .map(|px| {
                let a = px[1] as u32;
                ((px[0] as u32 * a + 255 * (255 - a)) / 255) as u8
            })
            .collect();
        (out, "DeviceGray")
    } else {
        (image.to_luma8().into_raw(), "DeviceGray")
    };
    ImagePage {
        width: image.width(),
        height: image.height(),
        color_space,
        pixels: Pixels::Raw(samples),
        dpi,
    }
}

/// Rebuild a `DynamicImage` from a page (used for thumbnails).
pub fn to_dynamic(page: &ImagePage) -> Result<DynamicImage, ImageError> {
    match &page.pixels {
        Pixels::Jpeg(bytes) => Ok(image::load_from_memory_with_format(
            bytes,
            ImageFormat::Jpeg,
        )?),
        Pixels::Raw(samples) => {
            if page.color_space == "DeviceGray" {
                image::GrayImage::from_raw(page.width, page.height, samples.clone())
                    .map(DynamicImage::ImageLuma8)
                    .ok_or_else(|| ImageError("gray buffer has the wrong size".into()))
            } else {
                image::RgbImage::from_raw(page.width, page.height, samples.clone())
                    .map(DynamicImage::ImageRgb8)
                    .ok_or_else(|| ImageError("rgb buffer has the wrong size".into()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TIFF (multi-page)
// ---------------------------------------------------------------------------

fn decode_tiff_pages(data: &[u8]) -> Result<Vec<ImagePage>, ImageError> {
    use tiff::decoder::{Decoder, DecodingResult};
    use tiff::tags::Tag;
    use tiff::ColorType as Tc;

    let mut decoder = Decoder::new(Cursor::new(data)).map_err(|e| ImageError(e.to_string()))?;
    let mut pages = Vec::new();
    loop {
        let (width, height) = decoder
            .dimensions()
            .map_err(|e| ImageError(e.to_string()))?;
        let color = decoder.colortype().map_err(|e| ImageError(e.to_string()))?;
        let dpi = {
            let unit = decoder
                .find_tag_unsigned::<u16>(Tag::ResolutionUnit)
                .ok()
                .flatten()
                .unwrap_or(2);
            let x = decoder.get_tag_f64(Tag::XResolution).ok();
            let y = decoder.get_tag_f64(Tag::YResolution).ok();
            match (x, y) {
                (Some(x), Some(y)) if x > 0.0 && y > 0.0 => match unit {
                    3 => Some((x * 2.54, y * 2.54)),
                    2 => Some((x, y)),
                    _ => None,
                },
                _ => None,
            }
        };
        let white_is_zero = decoder
            .find_tag_unsigned::<u16>(Tag::PhotometricInterpretation)
            .ok()
            .flatten()
            == Some(0);
        let result = decoder
            .read_image()
            .map_err(|e| ImageError(e.to_string()))?;
        let n = (width as usize) * (height as usize);

        let to_u8 = |result: DecodingResult| -> Result<Vec<u8>, ImageError> {
            Ok(match result {
                DecodingResult::U8(v) => v,
                DecodingResult::U16(v) => v.into_iter().map(|x| (x >> 8) as u8).collect(),
                DecodingResult::U32(v) => v.into_iter().map(|x| (x >> 24) as u8).collect(),
                DecodingResult::U64(v) => v.into_iter().map(|x| (x >> 56) as u8).collect(),
                DecodingResult::F32(v) => v
                    .into_iter()
                    .map(|x| (x.clamp(0.0, 1.0) * 255.0) as u8)
                    .collect(),
                DecodingResult::F64(v) => v
                    .into_iter()
                    .map(|x| (x.clamp(0.0, 1.0) * 255.0) as u8)
                    .collect(),
                _ => return Err(ImageError("unsupported TIFF sample format".into())),
            })
        };

        let page = match color {
            Tc::Gray(bits) => {
                let mut v = to_u8(result)?;
                if bits == 1 {
                    if v.len() == n {
                        for b in &mut v {
                            *b = if *b != 0 { 255 } else { 0 };
                        }
                    } else {
                        // Packed bits, one row per ceil(width/8) bytes.
                        let stride = (width as usize).div_ceil(8);
                        let mut out = Vec::with_capacity(n);
                        for row in 0..height as usize {
                            for x in 0..width as usize {
                                let byte = v.get(row * stride + x / 8).copied().unwrap_or(0);
                                out.push(if byte & (0x80 >> (x % 8)) != 0 {
                                    255
                                } else {
                                    0
                                });
                            }
                        }
                        v = out;
                    }
                } else if bits == 4 && v.len() == n {
                    for b in &mut v {
                        *b *= 17;
                    }
                }
                if v.len() != n {
                    return Err(ImageError("TIFF gray buffer has the wrong size".into()));
                }
                if white_is_zero {
                    for b in &mut v {
                        *b = 255 - *b;
                    }
                }
                ImagePage {
                    width,
                    height,
                    color_space: "DeviceGray",
                    pixels: Pixels::Raw(v),
                    dpi,
                }
            }
            Tc::GrayA(_) => {
                let v = to_u8(result)?;
                if v.len() != n * 2 {
                    return Err(ImageError(
                        "TIFF gray+alpha buffer has the wrong size".into(),
                    ));
                }
                let out = v
                    .chunks(2)
                    .map(|px| {
                        ((px[0] as u32 * px[1] as u32 + 255 * (255 - px[1] as u32)) / 255) as u8
                    })
                    .collect();
                ImagePage {
                    width,
                    height,
                    color_space: "DeviceGray",
                    pixels: Pixels::Raw(out),
                    dpi,
                }
            }
            Tc::RGB(_) => {
                let v = to_u8(result)?;
                if v.len() != n * 3 {
                    return Err(ImageError("TIFF RGB buffer has the wrong size".into()));
                }
                ImagePage {
                    width,
                    height,
                    color_space: "DeviceRGB",
                    pixels: Pixels::Raw(v),
                    dpi,
                }
            }
            Tc::RGBA(_) => {
                let v = to_u8(result)?;
                if v.len() != n * 4 {
                    return Err(ImageError("TIFF RGBA buffer has the wrong size".into()));
                }
                let mut out = Vec::with_capacity(n * 3);
                for px in v.chunks(4) {
                    let a = px[3] as u32;
                    for &channel in &px[..3] {
                        out.push(((channel as u32 * a + 255 * (255 - a)) / 255) as u8);
                    }
                }
                ImagePage {
                    width,
                    height,
                    color_space: "DeviceRGB",
                    pixels: Pixels::Raw(out),
                    dpi,
                }
            }
            Tc::CMYK(_) => {
                let v = to_u8(result)?;
                if v.len() != n * 4 {
                    return Err(ImageError("TIFF CMYK buffer has the wrong size".into()));
                }
                let mut out = Vec::with_capacity(n * 3);
                for px in v.chunks(4) {
                    let k = 255 - px[3] as u32;
                    for &channel in &px[..3] {
                        out.push(((255 - channel as u32) * k / 255) as u8);
                    }
                }
                ImagePage {
                    width,
                    height,
                    color_space: "DeviceRGB",
                    pixels: Pixels::Raw(out),
                    dpi,
                }
            }
            // Palette, YCbCr and friends: let the image crate handle the first page.
            _ => return Err(ImageError("unsupported TIFF colour type".into())),
        };
        pages.push(page);
        if !decoder.more_images() {
            break;
        }
        decoder
            .next_image()
            .map_err(|e| ImageError(e.to_string()))?;
    }
    Ok(pages)
}

// ---------------------------------------------------------------------------
// SVG
// ---------------------------------------------------------------------------

/// Rasterise an SVG. CSS pixels are 1/96 inch, so the page ends up the size the SVG declares.
fn render_svg(data: &[u8]) -> Result<ImagePage, ImageError> {
    let mut options = resvg::usvg::Options::default();
    options.fontdb_mut().load_system_fonts();
    let tree = resvg::usvg::Tree::from_data(data, &options)
        .map_err(|e| ImageError(format!("invalid SVG: {e}")))?;
    let size = tree.size();
    let (w, h) = (size.width().max(1.0), size.height().max(1.0));
    // Render at 3x for crisp output, capped so pathological sizes cannot exhaust memory.
    let scale = (3.0f32).min(6000.0 / w.max(h));
    let (pw, ph) = ((w * scale).ceil() as u32, (h * scale).ceil() as u32);
    let mut pixmap = resvg::tiny_skia::Pixmap::new(pw.max(1), ph.max(1))
        .ok_or_else(|| ImageError("SVG is too large to rasterise".into()))?;
    pixmap.fill(resvg::tiny_skia::Color::WHITE);
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let mut rgb = Vec::with_capacity((pw * ph * 3) as usize);
    for px in pixmap.pixels() {
        // Already composited on white, so alpha is 255 everywhere; demultiply defensively.
        let c = px.demultiply();
        rgb.extend_from_slice(&[c.red(), c.green(), c.blue()]);
    }
    let dpi = 96.0 * scale as f64;
    Ok(ImagePage {
        width: pw,
        height: ph,
        color_space: "DeviceRGB",
        pixels: Pixels::Raw(rgb),
        dpi: Some((dpi, dpi)),
    })
}

// ---------------------------------------------------------------------------
// DPI readers
// ---------------------------------------------------------------------------

fn png_dpi(data: &[u8]) -> Option<(f64, f64)> {
    if !data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return None;
    }
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        let kind = &data[pos + 4..pos + 8];
        if kind == b"pHYs" && pos + 8 + 9 <= data.len() {
            let x = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().ok()?) as f64;
            let y = u32::from_be_bytes(data[pos + 12..pos + 16].try_into().ok()?) as f64;
            let unit = data[pos + 16];
            return if unit == 1 && x > 0.0 && y > 0.0 {
                Some((x * 0.0254, y * 0.0254))
            } else {
                None
            };
        }
        if kind == b"IDAT" || kind == b"IEND" {
            return None;
        }
        pos += 12 + len;
    }
    None
}

fn jpeg_dpi(data: &[u8]) -> Option<(f64, f64)> {
    if !data.starts_with(&[0xFF, 0xD8]) {
        return None;
    }
    let mut pos = 2;
    let mut jfif: Option<(f64, f64)> = None;
    while pos + 4 <= data.len() {
        if data[pos] != 0xFF {
            pos += 1;
            continue;
        }
        let marker = data[pos + 1];
        if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 || marker == 0xFF {
            pos += if marker == 0xFF { 1 } else { 2 };
            continue;
        }
        if marker == 0xDA || marker == 0xD9 {
            break; // start of scan / end: no more headers
        }
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let seg = data.get(pos + 4..pos + 2 + len)?;
        if marker == 0xE0 && seg.starts_with(b"JFIF\0") && seg.len() >= 12 && jfif.is_none() {
            let unit = seg[7];
            let x = u16::from_be_bytes([seg[8], seg[9]]) as f64;
            let y = u16::from_be_bytes([seg[10], seg[11]]) as f64;
            jfif = match unit {
                1 if x > 0.0 && y > 0.0 => Some((x, y)),
                2 if x > 0.0 && y > 0.0 => Some((x * 2.54, y * 2.54)),
                _ => None,
            };
        }
        if marker == 0xE1 && seg.starts_with(b"Exif\0\0") {
            if let Some(dpi) = exif_dpi(&seg[6..]) {
                return Some(dpi);
            }
        }
        pos += 2 + len;
    }
    jfif
}

/// Read XResolution / YResolution / ResolutionUnit from a TIFF-structured EXIF block.
fn exif_dpi(tiff: &[u8]) -> Option<(f64, f64)> {
    if tiff.len() < 8 {
        return None;
    }
    let le = match &tiff[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |p: usize| -> Option<u16> {
        let b = tiff.get(p..p + 2)?;
        Some(if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let u32_at = |p: usize| -> Option<u32> {
        let b = tiff.get(p..p + 4)?;
        Some(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let ifd = u32_at(4)? as usize;
    let count = u16_at(ifd)? as usize;
    let (mut x, mut y, mut unit) = (None, None, 2u16);
    for i in 0..count.min(512) {
        let e = ifd + 2 + i * 12;
        let tag = u16_at(e)?;
        let typ = u16_at(e + 2)?;
        match tag {
            0x011A | 0x011B if typ == 5 => {
                let off = u32_at(e + 8)? as usize;
                let num = u32_at(off)? as f64;
                let den = u32_at(off + 4)? as f64;
                if den > 0.0 {
                    if tag == 0x011A {
                        x = Some(num / den);
                    } else {
                        y = Some(num / den);
                    }
                }
            }
            0x0128 if typ == 3 => unit = u16_at(e + 8)?,
            _ => {}
        }
    }
    let (x, y) = (x?, y.unwrap_or(x?));
    if x <= 0.0 || y <= 0.0 {
        return None;
    }
    match unit {
        3 => Some((x * 2.54, y * 2.54)),
        2 => Some((x, y)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};

    #[test]
    fn png_phys_is_read() {
        // 2x2 RGB PNG with a pHYs chunk of 300 DPI written by the image crate + manual chunk.
        let img: image::RgbImage = ImageBuffer::from_fn(2, 2, |_, _| Rgb([10u8, 20, 30]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        let mut bytes = buf.into_inner();
        // Insert a pHYs chunk right after IHDR (8 sig + 25 IHDR bytes).
        let ppm = (300.0f64 / 0.0254).round() as u32;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&9u32.to_be_bytes());
        chunk.extend_from_slice(b"pHYs");
        chunk.extend_from_slice(&ppm.to_be_bytes());
        chunk.extend_from_slice(&ppm.to_be_bytes());
        chunk.push(1);
        chunk.extend_from_slice(&[0, 0, 0, 0]); // crc not checked by our reader
        bytes.splice(33..33, chunk);
        let dpi = png_dpi(&bytes).unwrap();
        assert!((dpi.0 - 300.0).abs() < 0.5, "{dpi:?}");
    }

    #[test]
    fn jfif_density_is_read() {
        let img: image::RgbImage = ImageBuffer::from_fn(4, 4, |_, _| Rgb([1u8, 2, 3]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Jpeg).unwrap();
        let mut bytes = buf.into_inner();
        // Prepend a JFIF APP0 segment declaring 200 dpi.
        let app0 = [
            0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 1, 0, 200, 0, 200, 0, 0,
        ];
        bytes.splice(2..2, app0);
        assert_eq!(jpeg_dpi(&bytes), Some((200.0, 200.0)));
    }

    #[test]
    fn svg_renders_to_declared_size() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="96" height="48"><rect width="96" height="48" fill="red"/></svg>"#;
        let pages = decode_pages("box.svg", svg).unwrap();
        assert_eq!(pages.len(), 1);
        let p = &pages[0];
        assert_eq!((p.width, p.height), (288, 144));
        let dpi = p.dpi.unwrap();
        // 96 css px at 3x => 288 px at 288 dpi => 1 inch wide page.
        assert!((p.width as f64 / dpi.0 - 1.0).abs() < 0.01);
        if let Pixels::Raw(rgb) = &p.pixels {
            assert_eq!(&rgb[0..3], &[255, 0, 0]);
        } else {
            panic!("expected raw pixels");
        }
    }

    #[test]
    fn multipage_tiff_yields_every_page() {
        use tiff::encoder::{colortype, TiffEncoder};
        let mut buf = Cursor::new(Vec::new());
        {
            let mut enc = TiffEncoder::new(&mut buf).unwrap();
            for shade in [10u8, 200u8] {
                let pixels = vec![shade; 6 * 4];
                enc.write_image::<colortype::Gray8>(6, 4, &pixels).unwrap();
            }
        }
        let pages = decode_pages("scan.tif", &buf.into_inner()).unwrap();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].color_space, "DeviceGray");
        if let Pixels::Raw(v) = &pages[1].pixels {
            assert_eq!(v[0], 200);
        }
    }
}
