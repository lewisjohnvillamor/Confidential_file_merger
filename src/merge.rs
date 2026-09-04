//! Core merging logic: turns an ordered list of PDF and image inputs into one PDF.
//!
//! Everything here is pure, in-memory Rust. No network, no temp files, no
//! external binaries. PDFs are merged page-by-page with `lopdf`; images are
//! decoded with the `image` crate and embedded as PDF image XObjects (JPEGs are
//! passed through untouched, everything else is stored losslessly with Flate).

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;

use image::{ColorType, DynamicImage, ImageDecoder, ImageFormat, ImageReader};
use lopdf::{dictionary, Document, Object, ObjectId, Stream};

/// Largest page edge PDF viewers reliably accept (200 inches at 72 pt/in).
const MAX_PAGE_EDGE_PT: f64 = 14_400.0;

/// How image inputs are laid out on their PDF page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PageSize {
    /// Page is exactly the image size (1 pixel = 1 point).
    #[default]
    Fit,
    /// ISO A4, auto-oriented to match the image.
    A4,
    /// US Letter, auto-oriented to match the image.
    Letter,
}

impl PageSize {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fit" | "image" | "match" | "" => Some(PageSize::Fit),
            "a4" => Some(PageSize::A4),
            "letter" | "us_letter" | "us-letter" => Some(PageSize::Letter),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MergeOptions {
    pub page_size: PageSize,
    /// Margin in points around images placed on fixed-size pages.
    pub margin_pt: f64,
}

/// One input file: a display name (used in error messages) and its bytes.
#[derive(Debug, Clone)]
pub struct MergeInput {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Pdf,
    Image,
}

/// Supported file extensions (lowercase, without the dot).
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "pdf", "png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff",
];

/// Detect the input type from magic bytes, falling back to the file extension.
pub fn detect_kind(name: &str, data: &[u8]) -> Option<InputKind> {
    let head = &data[..data.len().min(1024)];
    if head.windows(4).any(|w| w == b"%PDF") {
        return Some(InputKind::Pdf);
    }
    if data.starts_with(&[0x89, b'P', b'N', b'G'])
        || data.starts_with(&[0xFF, 0xD8, 0xFF])
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || data.starts_with(b"BM")
        || (data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WEBP")
        || data.starts_with(b"II*\0")
        || data.starts_with(b"MM\0*")
    {
        return Some(InputKind::Image);
    }
    match extension(name).as_str() {
        "pdf" => Some(InputKind::Pdf),
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff" => Some(InputKind::Image),
        _ => None,
    }
}

pub fn extension(name: &str) -> String {
    name.rsplit('.')
        .next()
        .filter(|ext| ext.len() < name.len())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn is_supported_name(name: &str) -> bool {
    SUPPORTED_EXTENSIONS.contains(&extension(name).as_str())
}

#[derive(Debug)]
pub enum MergeError {
    NoInputs,
    Unsupported { name: String },
    Encrypted { name: String },
    NoPages { name: String },
    Pdf { name: String, source: lopdf::Error },
    Image { name: String, source: image::ImageError },
    Write(std::io::Error),
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeError::NoInputs => write!(f, "No input files were provided."),
            MergeError::Unsupported { name } => write!(
                f,
                "\"{name}\" is not a supported file type. Supported: PDF, PNG, JPEG, GIF, BMP, WebP, TIFF."
            ),
            MergeError::Encrypted { name } => write!(
                f,
                "\"{name}\" is password-protected. Remove the password first, then merge it."
            ),
            MergeError::NoPages { name } => write!(f, "\"{name}\" contains no pages."),
            MergeError::Pdf { name, source } => {
                write!(f, "\"{name}\" could not be read as a PDF: {source}")
            }
            MergeError::Image { name, source } => {
                write!(f, "\"{name}\" could not be decoded as an image: {source}")
            }
            MergeError::Write(source) => write!(f, "The merged PDF could not be written: {source}"),
        }
    }
}

impl std::error::Error for MergeError {}

/// Merge all inputs, in order, into a single PDF and return its bytes.
pub fn merge(inputs: &[MergeInput], options: MergeOptions) -> Result<Vec<u8>, MergeError> {
    if inputs.is_empty() {
        return Err(MergeError::NoInputs);
    }

    let mut out = Document::with_version("1.7");
    let mut next_id: u32 = 1;
    let mut page_ids: Vec<ObjectId> = Vec::new();

    for input in inputs {
        let kind = detect_kind(&input.name, &input.data).ok_or_else(|| MergeError::Unsupported {
            name: input.name.clone(),
        })?;
        let mut doc = match kind {
            InputKind::Pdf => load_pdf(input)?,
            InputKind::Image => image_to_document(input, options)?,
        };

        // Give this document's objects ids that don't collide with what we've collected so far.
        doc.renumber_objects_with(next_id);
        next_id = doc.max_id + 1;

        let pages: BTreeMap<u32, ObjectId> = doc.get_pages();
        if pages.is_empty() {
            return Err(MergeError::NoPages {
                name: input.name.clone(),
            });
        }

        // Copy inheritable attributes down onto each page before we throw away
        // the source page tree; otherwise pages would lose their size/resources.
        for &page_id in pages.values() {
            let inherited = collect_inherited(&doc, page_id);
            if let Ok(Object::Dictionary(page)) = doc.get_object_mut(page_id) {
                for (key, value) in inherited {
                    page.set(key, value);
                }
            }
            page_ids.push(page_id);
        }

        for (id, object) in doc.objects {
            match object.type_name().unwrap_or(b"") {
                // The merged document gets its own catalog and page tree; the
                // sources' outlines are dropped (they'd point into the wrong tree).
                b"Catalog" | b"Pages" | b"Outlines" | b"Outline" | b"XRef" | b"ObjStm" => {}
                _ => {
                    out.objects.insert(id, object);
                }
            }
        }
    }

    out.max_id = next_id;
    let pages_root_id = out.new_object_id();

    for &page_id in &page_ids {
        if let Ok(Object::Dictionary(page)) = out.get_object_mut(page_id) {
            page.set("Parent", pages_root_id);
        }
    }

    out.objects.insert(
        pages_root_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Count" => page_ids.len() as i64,
            "Kids" => page_ids.iter().map(|&id| Object::Reference(id)).collect::<Vec<_>>(),
        }),
    );

    let catalog_id = out.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_root_id,
    });
    let info_id = out.add_object(dictionary! {
        "Producer" => Object::string_literal("Confidential File Merger"),
    });
    out.trailer.set("Root", catalog_id);
    out.trailer.set("Info", info_id);

    // Drop everything that is no longer reachable from the new catalog
    // (old catalogs' name trees, metadata, structure trees, ...) and pack ids.
    out.prune_objects();
    out.renumber_objects();

    let mut buffer = Vec::new();
    out.save_to(&mut buffer).map_err(MergeError::Write)?;
    Ok(buffer)
}

fn load_pdf(input: &MergeInput) -> Result<Document, MergeError> {
    let encrypted = || MergeError::Encrypted {
        name: input.name.clone(),
    };
    let load = |bytes: &[u8]| {
        Document::load_mem(bytes).map_err(|source| match source {
            lopdf::Error::InvalidPassword | lopdf::Error::Decryption(_) => encrypted(),
            source => MergeError::Pdf {
                name: input.name.clone(),
                source,
            },
        })
    };

    let mut doc = load(&input.data)?;

    // lopdf decrypts on load (empty user password) only when /Encrypt is an indirect
    // reference. Some writers put the dictionary directly in the trailer; lopdf then
    // loads nothing at all. Rewrite such files as an incremental update that moves the
    // dictionary behind a reference, and load again through the normal path.
    if let Ok(Object::Dictionary(dict)) = doc.trailer.get(b"Encrypt").cloned() {
        let rewritten = with_indirect_encrypt(&input.data, &doc, &dict).ok_or_else(|| MergeError::Pdf {
            name: input.name.clone(),
            source: lopdf::Error::Unimplemented("no startxref found; cannot relocate the encryption dictionary"),
        })?;
        doc = load(&rewritten)?;
    }

    // Whatever is still in the trailer could not be opened with an empty password.
    if doc.trailer.get(b"Encrypt").is_ok() {
        return Err(encrypted());
    }
    Ok(doc)
}

/// Append an incremental update to `data` whose trailer references `encrypt` as an
/// indirect object instead of embedding it directly. Returns None if the file has no
/// parseable `startxref`.
fn with_indirect_encrypt(data: &[u8], doc: &Document, encrypt: &lopdf::Dictionary) -> Option<Vec<u8>> {
    let prev = last_startxref(data)?;
    let highest = doc
        .reference_table
        .entries
        .keys()
        .copied()
        .max()
        .unwrap_or(0)
        .max(doc.max_id);
    let new_id = highest + 1;

    let mut out = data.to_vec();
    if !out.ends_with(b"\n") && !out.ends_with(b"\r") {
        out.push(b'\n');
    }
    let obj_offset = out.len();
    out.extend_from_slice(format!("{new_id} 0 obj\n").as_bytes());
    write_object(&Object::Dictionary(encrypt.clone()), &mut out);
    out.extend_from_slice(b"\nendobj\n");

    let xref_offset = out.len();
    out.extend_from_slice(
        format!("xref\n0 1\n0000000000 65535 f \n{new_id} 1\n{obj_offset:010} 00000 n \n").as_bytes(),
    );

    let mut trailer = doc.trailer.clone();
    trailer.remove(b"Prev");
    trailer.remove(b"XRefStm");
    trailer.remove(b"Type");
    trailer.remove(b"Filter");
    trailer.remove(b"DecodeParms");
    trailer.remove(b"Length");
    trailer.remove(b"W");
    trailer.remove(b"Index");
    trailer.set("Encrypt", Object::Reference((new_id, 0)));
    trailer.set("Size", (new_id + 1) as i64);
    trailer.set("Prev", prev as i64);
    out.extend_from_slice(b"trailer\n");
    write_object(&Object::Dictionary(trailer), &mut out);
    out.extend_from_slice(format!("\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes());
    Some(out)
}

fn last_startxref(data: &[u8]) -> Option<usize> {
    let tail_start = data.len().saturating_sub(2048);
    let tail = &data[tail_start..];
    let pos = tail.windows(9).rposition(|w| w == b"startxref")?;
    let digits: String = tail[pos + 9..]
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    digits.parse().ok()
}

/// Minimal PDF object serializer (enough for an encryption dictionary).
fn write_object(object: &Object, out: &mut Vec<u8>) {
    match object {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(format!("{r}").as_bytes()),
        Object::Name(name) => {
            out.push(b'/');
            for &b in name {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+') {
                    out.push(b);
                } else {
                    out.extend_from_slice(format!("#{b:02X}").as_bytes());
                }
            }
        }
        Object::String(bytes, _) => {
            out.push(b'<');
            for b in bytes {
                out.extend_from_slice(format!("{b:02X}").as_bytes());
            }
            out.push(b'>');
        }
        Object::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(item, out);
            }
            out.push(b']');
        }
        Object::Dictionary(dict) => write_dictionary(dict, out),
        Object::Stream(stream) => write_dictionary(&stream.dict, out),
        Object::Reference((id, gen)) => out.extend_from_slice(format!("{id} {gen} R").as_bytes()),
    }
}

fn write_dictionary(dict: &lopdf::Dictionary, out: &mut Vec<u8>) {
    out.extend_from_slice(b"<<");
    for (key, value) in dict.iter() {
        write_object(&Object::Name(key.clone()), out);
        out.push(b' ');
        write_object(value, out);
        out.push(b' ');
    }
    out.extend_from_slice(b">>");
}

/// Walk up the `Parent` chain and gather attributes the page inherits but doesn't define itself.
fn collect_inherited(doc: &Document, page_id: ObjectId) -> Vec<(Vec<u8>, Object)> {
    const INHERITABLE: [&[u8]; 4] = [b"Resources", b"MediaBox", b"CropBox", b"Rotate"];
    let mut found: Vec<(Vec<u8>, Object)> = Vec::new();
    let Ok(page) = doc.get_dictionary(page_id) else {
        return found;
    };
    let mut missing: Vec<&[u8]> = INHERITABLE.iter().copied().filter(|k| !page.has(k)).collect();
    let mut current = page.get(b"Parent").and_then(Object::as_reference).ok();
    let mut depth = 0;
    while let (Some(parent_id), false) = (current, missing.is_empty()) {
        depth += 1;
        if depth > 64 {
            break;
        }
        let Ok(parent) = doc.get_dictionary(parent_id) else {
            break;
        };
        missing.retain(|key| {
            if let Ok(value) = parent.get(key) {
                found.push((key.to_vec(), value.clone()));
                false
            } else {
                true
            }
        });
        current = parent.get(b"Parent").and_then(Object::as_reference).ok();
    }
    found
}

/// Build a one-page PDF document containing the image.
fn image_to_document(input: &MergeInput, options: MergeOptions) -> Result<Document, MergeError> {
    let err = |source| MergeError::Image {
        name: input.name.clone(),
        source,
    };

    let reader = ImageReader::new(Cursor::new(&input.data))
        .with_guessed_format()
        .map_err(|e| err(image::ImageError::IoError(e)))?;
    let format = reader.format();
    let decoder = reader.into_decoder().map_err(err)?;
    let (width, height) = decoder.dimensions();
    let color = decoder.color_type();

    let image_stream = if format == Some(ImageFormat::Jpeg)
        && matches!(color, ColorType::Rgb8 | ColorType::L8)
    {
        // Baseline/progressive JPEG can be embedded as-is: no re-encoding, no quality loss.
        let color_space = if color == ColorType::Rgb8 { "DeviceRGB" } else { "DeviceGray" };
        Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => width as i64,
                "Height" => height as i64,
                "ColorSpace" => color_space,
                "BitsPerComponent" => 8,
                "Filter" => "DCTDecode",
            },
            input.data.clone(),
        )
    } else {
        let image = DynamicImage::from_decoder(decoder).map_err(err)?;
        let (samples, color_space) = flatten_samples(&image);
        let mut stream = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => width as i64,
                "Height" => height as i64,
                "ColorSpace" => color_space,
                "BitsPerComponent" => 8,
            },
            samples,
        );
        // Flate is lossless; if it doesn't help, lopdf leaves the stream raw.
        let _ = stream.compress();
        stream
    };

    let layout = Layout::compute(width, height, options);
    let content = format!(
        "q\n{w:.4} 0 0 {h:.4} {x:.4} {y:.4} cm\n/Im0 Do\nQ\n",
        w = layout.draw_w,
        h = layout.draw_h,
        x = layout.x,
        y = layout.y
    );

    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let image_id = doc.add_object(image_stream);
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), layout.page_w.into(), layout.page_h.into()],
        "Contents" => content_id,
        "Resources" => dictionary! {
            "XObject" => dictionary! { "Im0" => image_id },
        },
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);
    Ok(doc)
}

/// Convert any decoded image to 8-bit Gray or RGB samples, compositing alpha onto white.
fn flatten_samples(image: &DynamicImage) -> (Vec<u8>, &'static str) {
    let color = image.color();
    if color.has_color() {
        if color.has_alpha() {
            let rgba = image.to_rgba8();
            let mut out = Vec::with_capacity((rgba.width() * rgba.height() * 3) as usize);
            for px in rgba.pixels() {
                let a = px[3] as u32;
                for c in 0..3 {
                    out.push(((px[c] as u32 * a + 255 * (255 - a)) / 255) as u8);
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
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Layout {
    page_w: f64,
    page_h: f64,
    draw_w: f64,
    draw_h: f64,
    x: f64,
    y: f64,
}

impl Layout {
    fn compute(width: u32, height: u32, options: MergeOptions) -> Layout {
        let (iw, ih) = (width.max(1) as f64, height.max(1) as f64);
        let (page_w, page_h) = match options.page_size {
            PageSize::Fit => {
                let scale = (MAX_PAGE_EDGE_PT / iw.max(ih)).min(1.0);
                (iw * scale, ih * scale)
            }
            PageSize::A4 => oriented(595.276, 841.89, iw > ih),
            PageSize::Letter => oriented(612.0, 792.0, iw > ih),
        };
        let margin = options.margin_pt.max(0.0).min(page_w.min(page_h) / 4.0);
        let avail_w = page_w - 2.0 * margin;
        let avail_h = page_h - 2.0 * margin;
        let scale = (avail_w / iw).min(avail_h / ih);
        let draw_w = iw * scale;
        let draw_h = ih * scale;
        Layout {
            page_w,
            page_h,
            draw_w,
            draw_h,
            x: (page_w - draw_w) / 2.0,
            y: (page_h - draw_h) / 2.0,
        }
    }
}

fn oriented(short: f64, long: f64, landscape: bool) -> (f64, f64) {
    if landscape {
        (long, short)
    } else {
        (short, long)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};

    fn sample_pdf(pages: usize, text: &str) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        // Resources live on the Pages node so the inheritance path is exercised.
        let resources_id = doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let mut kids = Vec::new();
        for i in 0..pages {
            let content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 24.into()]),
                    Operation::new("Td", vec![72.into(), 700.into()]),
                    Operation::new("Tj", vec![Object::string_literal(format!("{text} {}", i + 1))]),
                    Operation::new("ET", vec![]),
                ],
            };
            let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
            let page_id = doc.add_object(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            });
            kids.push(Object::Reference(page_id));
        }
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => kids, "Count" => pages as i64,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    fn sample_png(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| Rgba([x as u8, y as u8, 128u8, if x % 2 == 0 { 255 } else { 0 }]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    fn sample_jpeg(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| Rgb([x as u8, y as u8, 200u8]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Jpeg).unwrap();
        buf.into_inner()
    }

    fn input(name: &str, data: Vec<u8>) -> MergeInput {
        MergeInput { name: name.to_string(), data }
    }

    fn page_count(pdf: &[u8]) -> usize {
        Document::load_mem(pdf).unwrap().get_pages().len()
    }

    #[test]
    fn merges_pdfs_in_order_and_keeps_inherited_attributes() {
        let merged = merge(
            &[input("a.pdf", sample_pdf(2, "A")), input("b.pdf", sample_pdf(3, "B"))],
            MergeOptions::default(),
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 5);
        for page_id in pages.values() {
            let page = doc.get_dictionary(*page_id).unwrap();
            assert!(page.has(b"MediaBox"), "MediaBox must be copied down from the Pages node");
            assert!(page.has(b"Resources"), "Resources must be copied down from the Pages node");
        }
        let first = doc.get_page_content(pages[&1]);
        let last = doc.get_page_content(pages[&5]);
        assert!(String::from_utf8_lossy(&first).contains("A 1"));
        assert!(String::from_utf8_lossy(&last).contains("B 3"));
    }

    #[test]
    fn merges_images_and_pdfs_together() {
        let merged = merge(
            &[
                input("scan.jpg", sample_jpeg(40, 30)),
                input("doc.pdf", sample_pdf(1, "D")),
                input("shot.png", sample_png(20, 50)),
            ],
            MergeOptions { page_size: PageSize::A4, margin_pt: 18.0 },
        )
        .unwrap();
        assert_eq!(page_count(&merged), 3);
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        // Landscape JPEG -> landscape A4.
        let mb = doc.get_dictionary(pages[&1]).unwrap().get(b"MediaBox").unwrap().as_array().unwrap().clone();
        assert!(mb[2].as_float().unwrap() > mb[3].as_float().unwrap());
        // Portrait PNG -> portrait A4.
        let mb = doc.get_dictionary(pages[&3]).unwrap().get(b"MediaBox").unwrap().as_array().unwrap().clone();
        assert!(mb[2].as_float().unwrap() < mb[3].as_float().unwrap());
    }

    #[test]
    fn jpeg_is_passed_through_without_reencoding() {
        let jpeg = sample_jpeg(16, 16);
        let merged = merge(&[input("x.jpg", jpeg.clone())], MergeOptions::default()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let has_dct = doc.objects.values().any(|o| {
            o.as_stream()
                .map(|s| s.dict.get(b"Filter").and_then(Object::as_name).ok() == Some(b"DCTDecode".as_slice()) && s.content == jpeg)
                .unwrap_or(false)
        });
        assert!(has_dct);
    }

    #[test]
    fn fit_page_matches_image_pixels() {
        let merged = merge(&[input("p.png", sample_png(120, 80))], MergeOptions::default()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        let mb = doc.get_dictionary(pages[&1]).unwrap().get(b"MediaBox").unwrap().as_array().unwrap().clone();
        assert_eq!(mb[2].as_float().unwrap(), 120.0);
        assert_eq!(mb[3].as_float().unwrap(), 80.0);
    }

    #[test]
    fn merging_the_output_again_works() {
        let once = merge(&[input("a.pdf", sample_pdf(2, "A")), input("i.png", sample_png(8, 8))], MergeOptions::default()).unwrap();
        let twice = merge(&[input("once.pdf", once.clone()), input("once2.pdf", once)], MergeOptions::default()).unwrap();
        assert_eq!(page_count(&twice), 6);
    }

    #[test]
    fn rejects_garbage_and_empty_input() {
        assert!(matches!(merge(&[], MergeOptions::default()), Err(MergeError::NoInputs)));
        let err = merge(&[input("notes.txt", b"hello".to_vec())], MergeOptions::default()).unwrap_err();
        assert!(matches!(err, MergeError::Unsupported { .. }));
        let err = merge(&[input("bad.pdf", b"%PDF-1.4 garbage".to_vec())], MergeOptions::default()).unwrap_err();
        assert!(matches!(err, MergeError::Pdf { .. }));
    }

    fn aes256_encrypted(pdf: &[u8], user_password: &str) -> Vec<u8> {
        use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
        use lopdf::{EncryptionState, EncryptionVersion, Permissions};
        use std::sync::Arc;
        let mut doc = Document::load_mem(pdf).unwrap();
        let key = [42u8; 32];
        let filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
        let state = EncryptionState::try_from(EncryptionVersion::V5 {
            encrypt_metadata: true,
            crypt_filters: std::collections::BTreeMap::from([(b"StdCF".to_vec(), filter)]),
            file_encryption_key: &key,
            stream_filter: b"StdCF".to_vec(),
            string_filter: b"StdCF".to_vec(),
            owner_password: "owner-secret",
            user_password,
            permissions: Permissions::all(),
        })
        .unwrap();
        doc.encrypt(&state).unwrap();
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn owner_locked_pdf_is_merged_readably() {
        // Owner password only (empty user password): must open and keep its text.
        let locked = aes256_encrypted(&sample_pdf(2, "Locked"), "");
        assert!(Document::load_mem(&locked).is_ok());
        let merged = merge(&[input("locked.pdf", locked), input("plain.pdf", sample_pdf(1, "Plain"))], MergeOptions::default()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 3);
        assert!(doc.trailer.get(b"Encrypt").is_err());
        assert!(String::from_utf8_lossy(&doc.get_page_content(pages[&2])).contains("Locked 2"));
        assert!(String::from_utf8_lossy(&doc.get_page_content(pages[&3])).contains("Plain 1"));
    }

    #[test]
    fn user_locked_pdf_is_rejected_clearly() {
        let locked = aes256_encrypted(&sample_pdf(1, "Secret"), "user-pw");
        let err = merge(&[input("secret.pdf", locked)], MergeOptions::default()).unwrap_err();
        assert!(matches!(err, MergeError::Encrypted { .. }), "got {err:?}");
        assert!(err.to_string().contains("password-protected"));
    }

    #[test]
    fn direct_encrypt_dictionary_fixtures() {
        // These fixtures (written by PyMuPDF) put /Encrypt directly in the trailer
        // rather than behind a reference, which lopdf does not decrypt on its own.
        let owner_locked = include_bytes!("../tests/fixtures/owner_locked.pdf");
        let user_locked = include_bytes!("../tests/fixtures/user_locked.pdf");

        let merged = merge(&[input("owner_locked.pdf", owner_locked.to_vec())], MergeOptions::default()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 2);
        let content = String::from_utf8_lossy(&doc.get_page_content(pages[&1])).into_owned();
        assert!(content.contains("BT") && content.contains("Tf"), "content stream should be readable, got {content:?}");

        let err = merge(&[input("user_locked.pdf", user_locked.to_vec())], MergeOptions::default()).unwrap_err();
        assert!(matches!(err, MergeError::Encrypted { .. }), "got {err:?}");
    }

    #[test]
    fn detects_kinds() {
        assert_eq!(detect_kind("x.bin", &sample_png(2, 2)), Some(InputKind::Image));
        assert_eq!(detect_kind("x.bin", &sample_pdf(1, "x")), Some(InputKind::Pdf));
        assert_eq!(detect_kind("photo.JPG", b""), Some(InputKind::Image));
        assert_eq!(detect_kind("readme.md", b"# hi"), None);
        assert!(is_supported_name("Scan 001.TIFF"));
        assert!(!is_supported_name("archive.zip"));
    }
}
