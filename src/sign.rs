//! Stamp transparent signature images onto PDF pages.
//!
//! Placements are expressed the way the GUI shows them: as fractions of the page *as
//! displayed* (origin top-left, y down), including the page's `/Rotate`. This module maps
//! that visual space back into the page's own coordinate system so the stamp lands
//! exactly where the user put it, whatever the page rotation, and applies the user's
//! own rotation on top.

use std::collections::BTreeMap;

use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream};

use crate::merge::{self, MergeError, MergeInput};
use crate::pagespec;

/// One signature stamp on one page. `cx`, `cy`, `width` and `height` are fractions of the
/// displayed page (0..1, origin top-left); `angle` is degrees clockwise on screen.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Placement {
    /// 1-based page number.
    pub page: u32,
    /// Index into the signature images passed alongside.
    #[serde(default)]
    pub image: usize,
    pub cx: f64,
    pub cy: f64,
    pub width: f64,
    pub height: f64,
    #[serde(default)]
    pub angle: f64,
}

/// Decoded signature pixels ready to become an image XObject with a soft mask.
struct SignatureImage {
    width: u32,
    height: u32,
    rgb: Vec<u8>,
    alpha: Vec<u8>,
}

fn decode_signature(index: usize, bytes: &[u8]) -> Result<SignatureImage, MergeError> {
    let image = image::load_from_memory(bytes).map_err(|e| MergeError::Image {
        name: format!("signature {}", index + 1),
        message: e.to_string(),
    })?;
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();
    let mut rgb = Vec::with_capacity((width * height * 3) as usize);
    let mut alpha = Vec::with_capacity((width * height) as usize);
    for px in rgba.pixels() {
        rgb.extend_from_slice(&px.0[..3]);
        alpha.push(px[3]);
    }
    Ok(SignatureImage {
        width,
        height,
        rgb,
        alpha,
    })
}

fn add_signature_xobject(doc: &mut Document, sig: &SignatureImage) -> ObjectId {
    let mut mask = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => sig.width as i64,
            "Height" => sig.height as i64,
            "ColorSpace" => "DeviceGray",
            "BitsPerComponent" => 8,
        },
        sig.alpha.clone(),
    );
    let _ = mask.compress();
    let mask_id = doc.add_object(mask);
    let mut image = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => sig.width as i64,
            "Height" => sig.height as i64,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
            "SMask" => mask_id,
        },
        sig.rgb.clone(),
    );
    let _ = image.compress();
    doc.add_object(image)
}

/// The page's displayed box (CropBox if present, else MediaBox) and its rotation.
pub(crate) struct PageGeometry {
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
    rotate: i32,
}

impl PageGeometry {
    fn visual_size(&self) -> (f64, f64) {
        let (w, h) = (self.x1 - self.x0, self.y1 - self.y0);
        if self.rotate % 180 == 90 {
            (h, w)
        } else {
            (w, h)
        }
    }

    /// Map a point in displayed-page points (origin top-left, y down) to user space.
    fn visual_to_user(&self, vx: f64, vy: f64) -> (f64, f64) {
        match self.rotate {
            90 => (self.x0 + vy, self.y0 + vx),
            180 => (self.x1 - vx, self.y0 + vy),
            270 => (self.x1 - vy, self.y1 - vx),
            _ => (self.x0 + vx, self.y1 - vy),
        }
    }
}

pub(crate) fn page_geometry(doc: &Document, page_id: ObjectId) -> PageGeometry {
    let inherited = merge::collect_inherited(doc, page_id);
    let page = doc.get_dictionary(page_id).ok();
    let lookup = |key: &[u8]| -> Option<Object> {
        page.and_then(|p| p.get(key).ok().cloned()).or_else(|| {
            inherited
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        })
    };
    let numbers = |object: Object| -> Option<Vec<f64>> {
        let object = match object {
            Object::Reference(id) => doc.get_object(id).ok()?.clone(),
            o => o,
        };
        let arr = object.as_array().ok()?;
        let v: Vec<f64> = arr
            .iter()
            .filter_map(|o| match o {
                Object::Reference(id) => doc.get_object(*id).ok().and_then(|x| x.as_float().ok()),
                o => o.as_float().ok(),
            })
            .map(|f| f as f64)
            .collect();
        (v.len() == 4).then_some(v)
    };
    let media = lookup(b"MediaBox")
        .and_then(numbers)
        .unwrap_or_else(|| vec![0.0, 0.0, 612.0, 792.0]);
    let mut b = lookup(b"CropBox")
        .and_then(numbers)
        .unwrap_or(media.clone());
    // Normalise corner order and keep the crop box inside the media box.
    let (mx0, my0, mx1, my1) = (
        media[0].min(media[2]),
        media[1].min(media[3]),
        media[0].max(media[2]),
        media[1].max(media[3]),
    );
    b = vec![
        b[0].min(b[2]).max(mx0),
        b[1].min(b[3]).max(my0),
        b[0].max(b[2]).min(mx1),
        b[1].max(b[3]).min(my1),
    ];
    if b[2] - b[0] < 1.0 || b[3] - b[1] < 1.0 {
        b = vec![mx0, my0, mx1, my1];
    }
    let rotate = lookup(b"Rotate")
        .and_then(|r| r.as_i64().ok())
        .map(pagespec::normalize_rotation)
        .unwrap_or(0);
    PageGeometry {
        x0: b[0],
        y0: b[1],
        x1: b[2],
        y1: b[3],
        rotate,
    }
}

/// Axis-aligned user-space rectangle `[x0 y0 x1 y1]` of a placement (rotation ignored).
pub(crate) fn placement_rect(geometry: &PageGeometry, placement: &Placement) -> [f64; 4] {
    let (vw, vh) = geometry.visual_size();
    let (cx, cy) = (placement.cx * vw, placement.cy * vh);
    let (hw, hh) = (
        placement.width.abs() * vw / 2.0,
        placement.height.abs() * vh / 2.0,
    );
    let corners = [
        geometry.visual_to_user(cx - hw, cy - hh),
        geometry.visual_to_user(cx + hw, cy - hh),
        geometry.visual_to_user(cx - hw, cy + hh),
        geometry.visual_to_user(cx + hw, cy + hh),
    ];
    let xs = corners.iter().map(|c| c.0);
    let ys = corners.iter().map(|c| c.1);
    [
        xs.clone().fold(f64::INFINITY, f64::min),
        ys.clone().fold(f64::INFINITY, f64::min),
        xs.fold(f64::NEG_INFINITY, f64::max),
        ys.fold(f64::NEG_INFINITY, f64::max),
    ]
}

/// Build the `cm` matrix that maps the unit square onto the stamp's rectangle.
fn stamp_matrix(geometry: &PageGeometry, placement: &Placement) -> [f64; 6] {
    let (vw, vh) = geometry.visual_size();
    let (cx, cy) = (placement.cx * vw, placement.cy * vh);
    let (hw, hh) = (
        placement.width.abs() * vw / 2.0,
        placement.height.abs() * vh / 2.0,
    );
    let theta = placement.angle.to_radians();
    let (sin, cos) = theta.sin_cos();
    // Clockwise on screen (y down).
    let corner = |dx: f64, dy: f64| -> (f64, f64) {
        let vx = cx + dx * cos - dy * sin;
        let vy = cy + dx * sin + dy * cos;
        geometry.visual_to_user(vx, vy)
    };
    let bottom_left = corner(-hw, hh);
    let bottom_right = corner(hw, hh);
    let top_left = corner(-hw, -hh);
    [
        bottom_right.0 - bottom_left.0,
        bottom_right.1 - bottom_left.1,
        top_left.0 - bottom_left.0,
        top_left.1 - bottom_left.1,
        bottom_left.0,
        bottom_left.1,
    ]
}

/// Stamp the signatures onto the PDF and return the new file's bytes.
pub fn sign(
    input: &MergeInput,
    signatures: &[Vec<u8>],
    placements: &[Placement],
) -> Result<Vec<u8>, MergeError> {
    if placements.is_empty() {
        return Err(MergeError::PageSelection {
            name: input.name.clone(),
            message: "no signature placement given".to_string(),
        });
    }
    let (mut doc, _) = merge::load_pdf(input)?;
    doc.encryption_state = None;
    let pages = doc.get_pages();
    let total = pages.len() as u32;
    if total == 0 {
        return Err(MergeError::NoPages {
            name: input.name.clone(),
        });
    }

    // Validate first so a bad placement fails before anything is modified.
    let mut by_page: BTreeMap<u32, Vec<&Placement>> = BTreeMap::new();
    for placement in placements {
        if placement.page == 0 || placement.page > total {
            return Err(MergeError::PageSelection {
                name: input.name.clone(),
                message: format!(
                    "page {} does not exist (the file has {total} pages)",
                    placement.page
                ),
            });
        }
        if placement.image >= signatures.len() {
            return Err(MergeError::PageSelection {
                name: input.name.clone(),
                message: format!("signature image {} was not provided", placement.image + 1),
            });
        }
        if !(placement.width > 0.0 && placement.height > 0.0) {
            return Err(MergeError::PageSelection {
                name: input.name.clone(),
                message: "signature size must be positive".to_string(),
            });
        }
        by_page.entry(placement.page).or_default().push(placement);
    }

    // Decode and embed only the signatures that are used.
    let mut xobjects: BTreeMap<usize, ObjectId> = BTreeMap::new();
    for placement in placements {
        if let std::collections::btree_map::Entry::Vacant(slot) = xobjects.entry(placement.image) {
            let decoded = decode_signature(placement.image, &signatures[placement.image])?;
            slot.insert(add_signature_xobject(&mut doc, &decoded));
        }
    }

    for (page_no, list) in by_page {
        let page_id = pages[&page_no];
        let geometry = page_geometry(&doc, page_id);

        let mut content = String::from("Q\n");
        for placement in list {
            let m = stamp_matrix(&geometry, placement);
            content.push_str(&format!(
                "q {:.4} {:.4} {:.4} {:.4} {:.4} {:.4} cm /CfmSig{} Do Q\n",
                m[0], m[1], m[2], m[3], m[4], m[5], placement.image
            ));
        }
        let open_id = doc.add_object(Stream::new(dictionary! {}, b"q\n".to_vec()));
        let stamp_id = doc.add_object(Stream::new(dictionary! {}, content.into_bytes()));

        // Resources: make sure the page has its own (direct) dictionary with our XObjects.
        let inherited = merge::collect_inherited(&doc, page_id);
        let mut resources = doc
            .get_dictionary(page_id)
            .ok()
            .and_then(|p| p.get(b"Resources").ok().cloned())
            .or_else(|| {
                inherited
                    .iter()
                    .find(|(k, _)| k == b"Resources")
                    .map(|(_, v)| v.clone())
            })
            .and_then(|r| resolve_dict(&doc, &r))
            .unwrap_or_default();
        let mut xobject_dict = resources
            .get(b"XObject")
            .ok()
            .and_then(|x| resolve_dict(&doc, x))
            .unwrap_or_default();
        for (index, id) in &xobjects {
            xobject_dict.set(format!("CfmSig{index}"), Object::Reference(*id));
        }
        resources.set("XObject", Object::Dictionary(xobject_dict));

        let existing: Vec<Object> = match doc
            .get_dictionary(page_id)
            .ok()
            .and_then(|p| p.get(b"Contents").ok().cloned())
        {
            Some(Object::Array(items)) => items,
            Some(Object::Reference(id)) => match doc.get_object(id) {
                Ok(Object::Array(items)) => items.clone(),
                _ => vec![Object::Reference(id)],
            },
            _ => Vec::new(),
        };
        let mut contents = vec![Object::Reference(open_id)];
        contents.extend(existing);
        contents.push(Object::Reference(stamp_id));

        if let Ok(Object::Dictionary(page)) = doc.get_object_mut(page_id) {
            page.set("Resources", Object::Dictionary(resources));
            page.set("Contents", Object::Array(contents));
        }
    }

    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(MergeError::Write)?;
    Ok(out)
}

fn resolve_dict(doc: &Document, object: &Object) -> Option<Dictionary> {
    match object {
        Object::Dictionary(d) => Some(d.clone()),
        Object::Reference(id) => doc.get_dictionary(*id).ok().cloned(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::tests::sample_pdf;
    use crate::preview::render_pdf_page_images;
    use image::{ImageBuffer, ImageFormat, Rgba};
    use std::io::Cursor;

    /// Opaque black rectangle with a transparent 4 px border.
    fn signature_png(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| {
            let inside = x >= 4 && y >= 4 && x < w - 4 && y < h - 4;
            Rgba([0u8, 0, 0, if inside { 255 } else { 0 }])
        });
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    fn place(page: u32, cx: f64, cy: f64, width: f64, height: f64, angle: f64) -> Placement {
        Placement {
            page,
            image: 0,
            cx,
            cy,
            width,
            height,
            angle,
        }
    }

    /// Render page `index` and report whether the pixel at visual fraction (fx, fy) is dark.
    fn dark_at(pdf: &[u8], index: usize, fx: f64, fy: f64) -> bool {
        let img = render_pdf_page_images(pdf.to_vec(), index, 1, 300).remove(0);
        let x = ((img.width() as f64 - 1.0) * fx).round() as u32;
        let y = ((img.height() as f64 - 1.0) * fy).round() as u32;
        let p = img.get_pixel(x, y);
        (p[0] as u32 + p[1] as u32 + p[2] as u32) < 200
    }

    fn rotated_sample(rotate: i64) -> Vec<u8> {
        let mut doc = Document::load_mem(&sample_pdf(1, "Rot")).unwrap();
        let page = doc.get_pages()[&1];
        if let Ok(Object::Dictionary(p)) = doc.get_object_mut(page) {
            p.set("Rotate", rotate);
        }
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn stamps_only_the_requested_page_with_a_soft_mask() {
        let input = MergeInput::new("doc.pdf", sample_pdf(2, "Doc"));
        let out = sign(
            &input,
            &[signature_png(80, 40)],
            &[place(2, 0.5, 0.5, 0.4, 0.2, 0.0)],
        )
        .unwrap();
        let doc = Document::load_mem(&out).unwrap();
        let pages = doc.get_pages();
        let p2 = doc.get_dictionary(pages[&2]).unwrap();
        let xobjects = p2
            .get(b"Resources")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"XObject")
            .unwrap()
            .as_dict()
            .unwrap();
        let sig = doc
            .get_object(xobjects.get(b"CfmSig0").unwrap().as_reference().unwrap())
            .unwrap()
            .as_stream()
            .unwrap();
        assert!(sig.dict.has(b"SMask"));
        assert_eq!(p2.get(b"Contents").unwrap().as_array().unwrap().len(), 3);
        let p1 = doc.get_dictionary(pages[&1]).unwrap();
        assert!(
            p1.get(b"Contents").unwrap().as_array().is_err(),
            "page 1 must be untouched"
        );
        // The original text is still there, and the page's fonts still resolve.
        assert!(String::from_utf8_lossy(&doc.get_page_content(pages[&2])).contains("Doc 2"));
        assert!(dark_at(&out, 1, 0.5, 0.5));
        assert!(!dark_at(&out, 1, 0.5, 0.15));
        assert!(!dark_at(&out, 0, 0.5, 0.5));
    }

    #[test]
    fn placement_follows_the_displayed_page_for_every_rotation() {
        for rotate in [0, 90, 180, 270] {
            let input = MergeInput::new("rot.pdf", rotated_sample(rotate));
            let out = sign(
                &input,
                &[signature_png(60, 60)],
                &[place(1, 0.25, 0.25, 0.2, 0.2, 0.0)],
            )
            .unwrap();
            assert!(
                dark_at(&out, 0, 0.25, 0.25),
                "rotate {rotate}: stamp missing at its spot"
            );
            assert!(
                !dark_at(&out, 0, 0.75, 0.75),
                "rotate {rotate}: stamp in the wrong place"
            );
            assert!(
                !dark_at(&out, 0, 0.75, 0.25),
                "rotate {rotate}: mirrored horizontally"
            );
            assert!(
                !dark_at(&out, 0, 0.25, 0.75),
                "rotate {rotate}: mirrored vertically"
            );
        }
    }

    #[test]
    fn angle_rotates_the_stamp_on_screen() {
        let input = MergeInput::new("doc.pdf", sample_pdf(1, "Doc"));
        // A wide stamp turned 90° must become tall.
        let out = sign(
            &input,
            &[signature_png(200, 40)],
            &[place(1, 0.5, 0.5, 0.5, 0.06, 90.0)],
        )
        .unwrap();
        assert!(dark_at(&out, 0, 0.5, 0.5));
        assert!(dark_at(&out, 0, 0.5, 0.65));
        assert!(!dark_at(&out, 0, 0.65, 0.5));
    }

    #[test]
    fn rejects_bad_placements_and_images() {
        let input = MergeInput::new("doc.pdf", sample_pdf(1, "Doc"));
        let sig = signature_png(10, 10);
        assert!(matches!(
            sign(
                &input,
                std::slice::from_ref(&sig),
                &[place(3, 0.5, 0.5, 0.1, 0.1, 0.0)]
            ),
            Err(MergeError::PageSelection { .. })
        ));
        assert!(matches!(
            sign(&input, std::slice::from_ref(&sig), &[]),
            Err(MergeError::PageSelection { .. })
        ));
        let mut wrong_image = place(1, 0.5, 0.5, 0.1, 0.1, 0.0);
        wrong_image.image = 2;
        assert!(matches!(
            sign(&input, &[sig], &[wrong_image]),
            Err(MergeError::PageSelection { .. })
        ));
        assert!(matches!(
            sign(
                &input,
                &[b"nope".to_vec()],
                &[place(1, 0.5, 0.5, 0.1, 0.1, 0.0)]
            ),
            Err(MergeError::Image { .. })
        ));
    }

    #[test]
    fn works_on_owner_locked_pdfs_and_outputs_plain_files() {
        let locked = include_bytes!("../tests/fixtures/owner_locked.pdf");
        let input = MergeInput::new("locked.pdf", locked.to_vec());
        let out = sign(
            &input,
            &[signature_png(30, 30)],
            &[place(1, 0.5, 0.5, 0.2, 0.2, 0.0)],
        )
        .unwrap();
        let doc = Document::load_mem(&out).unwrap();
        assert!(doc.trailer.get(b"Encrypt").is_err());
        assert!(dark_at(&out, 0, 0.5, 0.5));
    }
}
