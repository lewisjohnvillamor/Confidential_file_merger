//! Core merging logic: turns an ordered list of PDF and image inputs into one PDF.
//!
//! Everything here is pure, in-memory Rust. No network, no temp files, no
//! external binaries. PDFs are merged page-by-page with `lopdf`; images are
//! decoded by [`crate::images`] and embedded as PDF image XObjects.
//!
//! Beyond concatenation the merger:
//! * honours per-input page selections and rotations,
//! * opens owner-locked PDFs and user-locked ones given a password,
//! * sizes image pages from their DPI,
//! * builds an outline (one bookmark per file, source outlines nested underneath,
//!   named destinations resolved so internal links keep working),
//! * merges interactive forms, renaming colliding field names,
//! * de-duplicates identical streams (fonts, images) and compresses the rest.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};

use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream};

use crate::images::{self, ImagePage, Pixels};
use crate::pagespec;

/// Largest page edge PDF viewers reliably accept (200 inches at 72 pt/in).
const MAX_PAGE_EDGE_PT: f64 = 14_400.0;

/// How image inputs are laid out on their PDF page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PageSize {
    /// Page is the image's physical size (from its DPI), or 1 pixel = 1 point without one.
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

/// Document information written into the output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MergeOptions {
    pub page_size: PageSize,
    /// Margin in points around images placed on fixed-size pages.
    pub margin_pt: f64,
    /// Use the DPI declared by image files to compute the page size in `Fit` mode.
    pub use_image_dpi: bool,
    /// Add one bookmark per input file.
    pub bookmarks: bool,
    /// Keep the source PDFs' own outlines (nested under the file bookmark).
    pub keep_outlines: bool,
    /// Merge interactive form fields so they stay fillable.
    pub merge_forms: bool,
    /// De-duplicate identical streams and compress uncompressed ones.
    pub optimize: bool,
    /// Remove metadata that rides along hidden in the inputs: camera EXIF (including the
    /// GPS position) inside JPEGs, XMP packets, application data and edit timestamps.
    pub strip_metadata: bool,
    /// Encrypt the output with AES-256 so it opens only with this password.
    pub output_password: Option<String>,
    pub metadata: Metadata,
}

impl Default for MergeOptions {
    fn default() -> Self {
        MergeOptions {
            page_size: PageSize::Fit,
            margin_pt: 0.0,
            use_image_dpi: true,
            bookmarks: true,
            keep_outlines: true,
            merge_forms: true,
            optimize: true,
            strip_metadata: true,
            output_password: None,
            metadata: Metadata::default(),
        }
    }
}

/// One input file plus what to take from it.
#[derive(Debug, Clone, Default)]
pub struct MergeInput {
    /// Display name (used in error messages and bookmarks).
    pub name: String,
    pub data: Vec<u8>,
    /// Password for user-locked PDFs.
    pub password: Option<String>,
    /// 1-based page numbers, in output order. `None` means every page.
    pub pages: Option<Vec<u32>>,
    /// Alternative to `pages`: a selection string such as `1-3,5,odd`, resolved once the
    /// page count is known. Ignored when `pages` is set.
    pub page_spec: Option<String>,
    /// Extra rotation (0/90/180/270) applied to every selected page.
    pub rotate: i32,
    /// Additional per-page rotation, keyed by 1-based page number.
    pub page_rotations: BTreeMap<u32, i32>,
}

impl MergeInput {
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        MergeInput {
            name: name.into(),
            data,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Pdf,
    Image,
}

/// Supported file extensions (lowercase, without the dot).
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "pdf", "png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "svg", "svgz",
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
        || images::looks_like_svg(name, data)
    {
        return Some(InputKind::Image);
    }
    match extension(name).as_str() {
        "pdf" => Some(InputKind::Pdf),
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "svg" | "svgz" => {
            Some(InputKind::Image)
        }
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
    Unsupported {
        name: String,
    },
    /// Needs a user password and none was given.
    Encrypted {
        name: String,
    },
    /// A password was given but it is wrong.
    WrongPassword {
        name: String,
    },
    NoPages {
        name: String,
    },
    PageSelection {
        name: String,
        message: String,
    },
    Pdf {
        name: String,
        source: lopdf::Error,
    },
    Image {
        name: String,
        message: String,
    },
    Write(std::io::Error),
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeError::NoInputs => write!(f, "No input files were provided."),
            MergeError::Unsupported { name } => write!(
                f,
                "\"{name}\" is not a supported file type. Supported: PDF, PNG, JPEG, GIF, BMP, WebP, TIFF, SVG."
            ),
            MergeError::Encrypted { name } => {
                write!(f, "\"{name}\" is password-protected. Enter its password to include it.")
            }
            MergeError::WrongPassword { name } => write!(f, "The password for \"{name}\" is incorrect."),
            MergeError::NoPages { name } => write!(f, "\"{name}\" contains no pages."),
            MergeError::PageSelection { name, message } => {
                write!(f, "Page selection for \"{name}\": {message}.")
            }
            MergeError::Pdf { name, source } => {
                write!(f, "\"{name}\" could not be read as a PDF: {source}")
            }
            MergeError::Image { name, message } => {
                write!(f, "\"{name}\" could not be decoded as an image: {message}")
            }
            MergeError::Write(source) => write!(f, "The merged PDF could not be written: {source}"),
        }
    }
}

impl std::error::Error for MergeError {}

/// Progress report emitted while merging.
#[derive(Debug, Clone)]
pub struct Progress {
    pub step: usize,
    pub total: usize,
    pub label: String,
}

/// Merge all inputs, in order, into a single PDF and return its bytes.
pub fn merge(inputs: &[MergeInput], options: &MergeOptions) -> Result<Vec<u8>, MergeError> {
    merge_with_progress(inputs, options, |_| {})
}

/// Like [`merge`], reporting progress after each input and each finishing stage.
pub fn merge_with_progress(
    inputs: &[MergeInput],
    options: &MergeOptions,
    mut progress: impl FnMut(Progress),
) -> Result<Vec<u8>, MergeError> {
    if inputs.is_empty() {
        return Err(MergeError::NoInputs);
    }
    let total_steps = inputs.len() + 3;
    let mut report = |step: usize, label: String| {
        progress(Progress {
            step,
            total: total_steps,
            label,
        })
    };

    let mut out = Document::with_version("1.7");
    let mut next_id: u32 = 1;
    let mut page_ids: Vec<ObjectId> = Vec::new();
    let mut sections: Vec<Section> = Vec::new();

    for (index, input) in inputs.iter().enumerate() {
        report(index, format!("Reading {}", input.name));
        let kind =
            detect_kind(&input.name, &input.data).ok_or_else(|| MergeError::Unsupported {
                name: input.name.clone(),
            })?;
        let mut doc = match kind {
            InputKind::Pdf => load_pdf(input)?.0,
            InputKind::Image => image_document(input, options)?,
        };

        // Give this document's objects ids that don't collide with what we've collected so far.
        doc.renumber_objects_with(next_id);
        next_id = doc.max_id + 1;

        let all_pages: BTreeMap<u32, ObjectId> = doc.get_pages();
        if all_pages.is_empty() {
            return Err(MergeError::NoPages {
                name: input.name.clone(),
            });
        }
        let total = all_pages.len() as u32;
        let selection: Vec<u32> = match (&input.pages, &input.page_spec) {
            (None, Some(spec)) => pagespec::parse_page_spec(spec, total).map_err(|message| {
                MergeError::PageSelection {
                    name: input.name.clone(),
                    message,
                }
            })?,
            (None, None) => (1..=total).collect(),
            (Some(pages), _) => {
                for &p in pages {
                    if p == 0 || p > total {
                        return Err(MergeError::PageSelection {
                            name: input.name.clone(),
                            message: format!(
                                "page {p} does not exist (the file has {total} pages)"
                            ),
                        });
                    }
                }
                if pages.is_empty() {
                    return Err(MergeError::PageSelection {
                        name: input.name.clone(),
                        message: "no pages selected".to_string(),
                    });
                }
                pages.clone()
            }
        };

        // Copy inheritable attributes down onto each page before we throw away the
        // source page tree; otherwise pages would lose their size/resources.
        let mut kept: BTreeSet<ObjectId> = BTreeSet::new();
        let mut base_rotation: HashMap<ObjectId, i64> = HashMap::new();
        let mut section_pages = Vec::new();
        for page_no in selection {
            let original_id = all_pages[&page_no];
            let inherited = collect_inherited(&doc, original_id);
            if let std::collections::hash_map::Entry::Vacant(slot) =
                base_rotation.entry(original_id)
            {
                let own = doc
                    .get_dictionary(original_id)
                    .ok()
                    .and_then(|p| p.get(b"Rotate").and_then(Object::as_i64).ok());
                let inherited_rot = inherited
                    .iter()
                    .find(|(k, _)| k == b"Rotate")
                    .and_then(|(_, v)| v.as_i64().ok());
                slot.insert(own.or(inherited_rot).unwrap_or(0));
            }
            // A page selected twice must become two page objects (a page has one parent).
            let page_id = if kept.contains(&original_id) {
                let clone = doc
                    .get_object(original_id)
                    .map_err(|e| pdf_err(input, e))?
                    .clone();
                doc.max_id = doc.max_id.max(next_id - 1);
                let id = doc.add_object(clone);
                next_id = doc.max_id + 1;
                id
            } else {
                original_id
            };
            kept.insert(original_id);
            let rotation = pagespec::normalize_rotation(
                (input.rotate + input.page_rotations.get(&page_no).copied().unwrap_or(0)) as i64,
            );
            if let Ok(Object::Dictionary(page)) = doc.get_object_mut(page_id) {
                for (key, value) in inherited {
                    page.set(key, value);
                }
                if rotation != 0 {
                    let existing = base_rotation[&original_id];
                    page.set(
                        "Rotate",
                        pagespec::normalize_rotation(existing + rotation as i64) as i64,
                    );
                }
            }
            section_pages.push(page_id);
        }

        // Named destinations only live in the catalog we are about to drop: inline them
        // so outline entries and internal links keep pointing at the right pages.
        resolve_named_destinations(&mut doc);

        let catalog = catalog_dict(&doc);
        let outline_root = if options.keep_outlines {
            catalog
                .as_ref()
                .and_then(|c| c.get(b"Outlines").and_then(Object::as_reference).ok())
        } else {
            None
        };
        let acroform = if options.merge_forms {
            catalog
                .as_ref()
                .and_then(|c| resolve_dict(&doc, c.get(b"AcroForm").ok()?))
        } else {
            None
        };

        sections.push(Section {
            title: display_title(&input.name),
            first_page: section_pages[0],
            kept_pages: kept,
            outline_root,
            acroform,
        });
        page_ids.extend(section_pages);

        for (id, object) in doc.objects {
            match object.type_name().unwrap_or(b"") {
                // The merged document gets its own catalog and page tree.
                b"Catalog" | b"Pages" | b"XRef" | b"ObjStm" => {}
                b"Outlines" if !options.keep_outlines => {}
                _ => {
                    out.objects.insert(id, object);
                }
            }
        }
    }

    report(inputs.len(), "Building page tree and outline".to_string());
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

    let mut catalog = dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_root_id,
    };
    if let Some(outlines_id) = build_outlines(&mut out, &sections, options) {
        catalog.set("Outlines", outlines_id);
        catalog.set("PageMode", "UseOutlines");
    }
    if options.merge_forms {
        if let Some(acroform_id) = build_acroform(&mut out, &sections) {
            catalog.set("AcroForm", acroform_id);
        }
    }
    let catalog_id = out.add_object(catalog);

    let mut info = dictionary! {
        "Producer" => Object::string_literal("Confidential File Merger"),
    };
    for (key, value) in [
        ("Title", &options.metadata.title),
        ("Author", &options.metadata.author),
        ("Subject", &options.metadata.subject),
        ("Keywords", &options.metadata.keywords),
    ] {
        if let Some(v) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            info.set(key, text_string(v));
        }
    }
    let info_id = out.add_object(info);
    out.trailer.set("Root", catalog_id);
    out.trailer.set("Info", info_id);

    if options.strip_metadata {
        scrub_hidden_metadata(&mut out);
    }

    // Drop everything that is no longer reachable from the new catalog
    // (old catalogs' name trees, metadata, structure trees, ...).
    out.prune_objects();

    if options.optimize {
        report(inputs.len() + 1, "Optimising".to_string());
        dedupe_streams(&mut out);
        out.prune_objects();
        out.compress();
    }

    report(inputs.len() + 2, "Writing".to_string());
    out.renumber_objects();
    if let Some(password) = options.output_password.as_deref().filter(|p| !p.is_empty()) {
        protect_with_password(&mut out, password)?;
    }
    let mut buffer = Vec::new();
    out.save_to(&mut buffer).map_err(MergeError::Write)?;
    Ok(buffer)
}

/// Encrypt the finished document with AES-256 (the PDF 2.0 standard security handler,
/// revision 6), so that it opens only with `password`.
///
/// The same password is also the owner password and every permission is granted: this
/// protects the file in transit and at rest, which is what people merging bank statements
/// need. It is deliberately not a copy-protection scheme, which PDF cannot enforce anyway.
fn protect_with_password(doc: &mut Document, password: &str) -> Result<(), MergeError> {
    use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
    use lopdf::{EncryptionState, EncryptionVersion, Permissions};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let failed = |e: lopdf::Error| {
        MergeError::Write(std::io::Error::other(format!("encryption failed: {e}")))
    };
    // An encrypted file must carry a file identifier; a random one says nothing about
    // where or when the file was made.
    let id: [u8; 16] = rand::random();
    doc.trailer.set(
        "ID",
        vec![
            Object::String(id.to_vec(), lopdf::StringFormat::Hexadecimal),
            Object::String(id.to_vec(), lopdf::StringFormat::Hexadecimal),
        ],
    );
    let mut file_key = [0u8; 32];
    rand::fill(&mut file_key);
    let filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), filter)]),
        file_encryption_key: &file_key,
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: password,
        user_password: password,
        permissions: Permissions::all(),
    })
    .map_err(failed)?;
    doc.encrypt(&state).map_err(failed)
}

/// What one input contributed, needed for the outline and form passes.
struct Section {
    title: String,
    first_page: ObjectId,
    kept_pages: BTreeSet<ObjectId>,
    outline_root: Option<ObjectId>,
    acroform: Option<Dictionary>,
}

fn pdf_err(input: &MergeInput, source: lopdf::Error) -> MergeError {
    MergeError::Pdf {
        name: input.name.clone(),
        source,
    }
}

/// File name without directories or extension, for bookmarks.
fn display_title(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && ext.len() <= 5 => stem.to_string(),
        _ => base.to_string(),
    }
}

/// Encode text for a PDF string: PDFDocEncoding when it fits, UTF-16BE with BOM otherwise.
fn text_string(s: &str) -> Object {
    if s.is_ascii() {
        Object::string_literal(s)
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for unit in s.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Object::String(bytes, lopdf::StringFormat::Literal)
    }
}

fn catalog_dict(doc: &Document) -> Option<Dictionary> {
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .ok()?;
    doc.get_dictionary(root).ok().cloned()
}

fn resolve_dict(doc: &Document, object: &Object) -> Option<Dictionary> {
    match object {
        Object::Dictionary(d) => Some(d.clone()),
        Object::Reference(id) => doc.get_dictionary(*id).ok().cloned(),
        _ => None,
    }
}

/// Page width/height in points, honouring /Rotate.
pub fn page_size_pt(doc: &Document, page_id: ObjectId) -> (f32, f32) {
    let mut w = 612.0;
    let mut h = 792.0;
    let mut rotate = 0;
    if let Ok(page) = doc.get_dictionary(page_id) {
        let inherited = collect_inherited(doc, page_id);
        let lookup = |key: &[u8]| -> Option<Object> {
            page.get(key).ok().cloned().or_else(|| {
                inherited
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.clone())
            })
        };
        if let Some(mb) = lookup(b"MediaBox") {
            let mb = match mb {
                Object::Reference(id) => doc.get_object(id).ok().cloned().unwrap_or(Object::Null),
                other => other,
            };
            if let Ok(arr) = mb.as_array() {
                let v: Vec<f32> = arr
                    .iter()
                    .map(|o| match o {
                        Object::Reference(id) => doc
                            .get_object(*id)
                            .and_then(Object::as_float)
                            .unwrap_or(0.0),
                        o => o.as_float().unwrap_or(0.0),
                    })
                    .collect();
                if v.len() == 4 {
                    w = (v[2] - v[0]).abs();
                    h = (v[3] - v[1]).abs();
                }
            }
        }
        if let Some(r) = lookup(b"Rotate") {
            rotate = r.as_i64().unwrap_or(0);
        }
    }
    if pagespec::normalize_rotation(rotate) % 180 == 90 {
        (h, w)
    } else {
        (w, h)
    }
}

/// Load a PDF, decrypting it if possible. Returns the document and whether it was encrypted.
pub fn load_pdf(input: &MergeInput) -> Result<(Document, bool), MergeError> {
    let name = || input.name.clone();
    let pdf_err = |source: lopdf::Error| MergeError::Pdf {
        name: name(),
        source,
    };
    let load = |bytes: &[u8], password: Option<&str>| -> Result<Document, MergeError> {
        let options = lopdf::LoadOptions {
            password: password.map(str::to_string),
            ..Default::default()
        };
        Document::load_mem_with_options(bytes, options).map_err(|source| match source {
            lopdf::Error::InvalidPassword | lopdf::Error::Decryption(_) => {
                if password.is_some() {
                    MergeError::WrongPassword { name: name() }
                } else {
                    MergeError::Encrypted { name: name() }
                }
            }
            source => pdf_err(source),
        })
    };

    // First pass without a password: opens plain files and owner-locked ones outright.
    let mut doc = load(&input.data, None)?;
    let mut was_encrypted = doc.was_encrypted();
    let mut bytes: std::borrow::Cow<[u8]> = std::borrow::Cow::Borrowed(&input.data);

    // lopdf decrypts on load only when /Encrypt is an indirect reference. Some writers
    // put the dictionary directly in the trailer; lopdf then loads nothing at all.
    // Rewrite such files as an incremental update that moves the dictionary behind a
    // reference, and load again through the normal path.
    if let Ok(Object::Dictionary(dict)) = doc.trailer.get(b"Encrypt").cloned() {
        let rewritten = with_indirect_encrypt(&input.data, &doc, &dict).ok_or_else(|| {
            pdf_err(lopdf::Error::Unimplemented(
                "no startxref found; cannot relocate the encryption dictionary",
            ))
        })?;
        bytes = std::borrow::Cow::Owned(rewritten);
        doc = load(&bytes, None)?;
        was_encrypted = true;
    }

    // Still locked: a user password is required.
    if doc.trailer.get(b"Encrypt").is_ok() {
        let Some(password) = input.password.as_deref().filter(|p| !p.is_empty()) else {
            return Err(MergeError::Encrypted { name: name() });
        };
        doc = load(&bytes, Some(password))?;
        was_encrypted = true;
        if doc.trailer.get(b"Encrypt").is_ok() {
            return Err(MergeError::WrongPassword { name: name() });
        }
    }
    Ok((doc, was_encrypted))
}

/// Append an incremental update to `data` whose trailer references `encrypt` as an
/// indirect object instead of embedding it directly. Returns None if the file has no
/// parseable `startxref`.
fn with_indirect_encrypt(data: &[u8], doc: &Document, encrypt: &Dictionary) -> Option<Vec<u8>> {
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
        format!("xref\n0 1\n0000000000 65535 f \n{new_id} 1\n{obj_offset:010} 00000 n \n")
            .as_bytes(),
    );

    let mut trailer = doc.trailer.clone();
    for key in [
        b"Prev".as_slice(),
        b"XRefStm",
        b"Type",
        b"Filter",
        b"DecodeParms",
        b"Length",
        b"W",
        b"Index",
    ] {
        trailer.remove(key);
    }
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

/// Minimal PDF object serializer (used for the encryption-dictionary rewrite and for
/// hashing stream dictionaries).
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

fn write_dictionary(dict: &Dictionary, out: &mut Vec<u8>) {
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
pub(crate) fn collect_inherited(doc: &Document, page_id: ObjectId) -> Vec<(Vec<u8>, Object)> {
    const INHERITABLE: [&[u8]; 4] = [b"Resources", b"MediaBox", b"CropBox", b"Rotate"];
    let mut found: Vec<(Vec<u8>, Object)> = Vec::new();
    let Ok(page) = doc.get_dictionary(page_id) else {
        return found;
    };
    let mut missing: Vec<&[u8]> = INHERITABLE
        .iter()
        .copied()
        .filter(|k| !page.has(k))
        .collect();
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

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

/// Build a PDF document with one page per image page.
fn image_document(input: &MergeInput, options: &MergeOptions) -> Result<Document, MergeError> {
    let pages = images::decode_pages(&input.name, &input.data).map_err(|e| MergeError::Image {
        name: input.name.clone(),
        message: e.0,
    })?;
    if pages.is_empty() {
        return Err(MergeError::NoPages {
            name: input.name.clone(),
        });
    }
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let mut kids = Vec::new();
    for page in &pages {
        kids.push(Object::Reference(add_image_page(
            &mut doc,
            pages_id,
            page,
            options,
            &input.name,
        )?));
    }
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => kids,
            "Count" => pages.len() as i64,
        }),
    );
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    Ok(doc)
}

fn add_image_page(
    doc: &mut Document,
    pages_id: ObjectId,
    page: &ImagePage,
    options: &MergeOptions,
    name: &str,
) -> Result<ObjectId, MergeError> {
    let mut dict = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Image",
        "Width" => page.width as i64,
        "Height" => page.height as i64,
        "ColorSpace" => page.color_space,
        "BitsPerComponent" => 8,
    };
    let jpeg = match &page.pixels {
        Pixels::Jpeg(bytes) if options.strip_metadata => images::strip_jpeg_metadata(bytes),
        Pixels::Jpeg(bytes) => Some(bytes.clone()),
        Pixels::Raw(_) => None,
    };
    let stream = match (&page.pixels, jpeg) {
        (_, Some(bytes)) => {
            dict.set("Filter", "DCTDecode");
            Stream::new(dict, bytes)
        }
        (Pixels::Raw(samples), None) => {
            let mut s = Stream::new(dict, samples.clone());
            let _ = s.compress();
            s
        }
        // A JPEG too unusual to strip safely: embed its decoded pixels instead, so the
        // original bytes (and whatever they carry) never reach the output.
        (Pixels::Jpeg(_), None) => {
            let decoded = images::to_dynamic(page).map_err(|e| MergeError::Image {
                name: name.to_string(),
                message: e.0,
            })?;
            let raw = images::from_dynamic(&decoded, page.dpi);
            dict.set("ColorSpace", raw.color_space);
            let samples = match raw.pixels {
                Pixels::Raw(samples) => samples,
                Pixels::Jpeg(_) => unreachable!("from_dynamic always yields raw samples"),
            };
            let mut s = Stream::new(dict, samples);
            let _ = s.compress();
            s
        }
    };
    let layout = Layout::compute(page, options);
    let content = format!(
        "q\n{w:.4} 0 0 {h:.4} {x:.4} {y:.4} cm\n/Im0 Do\nQ\n",
        w = layout.draw_w,
        h = layout.draw_h,
        x = layout.x,
        y = layout.y
    );
    let image_id = doc.add_object(stream);
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    Ok(doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), layout.page_w.into(), layout.page_h.into()],
        "Contents" => content_id,
        "Resources" => dictionary! {
            "XObject" => dictionary! { "Im0" => image_id },
        },
    }))
}

/// Remove metadata that travels hidden inside the merged document: XMP packets and
/// application data attached to pages, images and forms, edit timestamps, and camera
/// metadata inside embedded JPEG images (a phone-scanned PDF often carries the photo's
/// GPS position). Nothing drawn on any page changes.
fn scrub_hidden_metadata(doc: &mut Document) {
    for object in doc.objects.values_mut() {
        let dict = match object {
            Object::Dictionary(dict) => dict,
            Object::Stream(stream) => {
                if is_plain_jpeg(&stream.dict) {
                    // Unusual JPEGs are left as they are rather than risk a broken page.
                    if let Some(clean) = images::strip_jpeg_metadata(&stream.content) {
                        stream.set_content(clean);
                    }
                }
                &mut stream.dict
            }
            _ => continue,
        };
        for key in [&b"Metadata"[..], b"PieceInfo", b"LastModified"] {
            dict.remove(key);
        }
    }
}

/// A stream whose only filter is `DCTDecode`, i.e. whose bytes are a JPEG file.
fn is_plain_jpeg(dict: &lopdf::Dictionary) -> bool {
    match dict.get(b"Filter") {
        Ok(Object::Name(name)) => name == b"DCTDecode",
        Ok(Object::Array(filters)) => {
            matches!(filters.as_slice(), [Object::Name(name)] if name == b"DCTDecode")
        }
        _ => false,
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
    fn compute(page: &ImagePage, options: &MergeOptions) -> Layout {
        let (iw, ih) = (page.width.max(1) as f64, page.height.max(1) as f64);
        let (page_w, page_h) = match options.page_size {
            PageSize::Fit => {
                let dpi = page
                    .dpi
                    .filter(|_| options.use_image_dpi)
                    .filter(|(x, y)| (30.0..=2400.0).contains(x) && (30.0..=2400.0).contains(y));
                let (w, h) = match dpi {
                    Some((dx, dy)) => (iw * 72.0 / dx, ih * 72.0 / dy),
                    None => (iw, ih),
                };
                let scale = (MAX_PAGE_EDGE_PT / w.max(h)).min(1.0);
                (w * scale, h * scale)
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

// ---------------------------------------------------------------------------
// Named destinations and outlines
// ---------------------------------------------------------------------------

/// Replace string/name destinations (`/Dest (name)` and `/A << /S /GoTo /D (name) >>`)
/// with the explicit destination arrays they refer to.
fn resolve_named_destinations(doc: &mut Document) {
    let Some(catalog) = catalog_dict(doc) else {
        return;
    };
    let mut names: HashMap<Vec<u8>, Object> = HashMap::new();
    if let Some(dests) = catalog
        .get(b"Dests")
        .ok()
        .and_then(|o| resolve_dict(doc, o))
    {
        for (key, value) in dests.iter() {
            if let Some(dest) = dest_array(doc, value) {
                names.insert(key.clone(), dest);
            }
        }
    }
    if let Some(name_dict) = catalog
        .get(b"Names")
        .ok()
        .and_then(|o| resolve_dict(doc, o))
    {
        if let Ok(tree) = name_dict.get(b"Dests") {
            collect_name_tree(doc, tree, &mut names, 0);
        }
    }
    if names.is_empty() {
        return;
    }
    for object in doc.objects.values_mut() {
        rewrite_dests(object, &names, 0);
    }
}

fn dest_array(doc: &Document, value: &Object) -> Option<Object> {
    match value {
        Object::Array(_) => Some(value.clone()),
        Object::Dictionary(d) => d.get(b"D").ok().and_then(|d| dest_array(doc, d)),
        Object::Reference(id) => dest_array(doc, doc.get_object(*id).ok()?),
        _ => None,
    }
}

fn collect_name_tree(
    doc: &Document,
    node: &Object,
    names: &mut HashMap<Vec<u8>, Object>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    let Some(node) = resolve_dict(doc, node) else {
        return;
    };
    if let Ok(entries) = node.get(b"Names").and_then(|n| resolve_array(doc, n)) {
        for pair in entries.chunks(2) {
            if let [key, value] = pair {
                let key = match key {
                    Object::String(s, _) => s.clone(),
                    Object::Reference(id) => match doc.get_object(*id) {
                        Ok(Object::String(s, _)) => s.clone(),
                        _ => continue,
                    },
                    _ => continue,
                };
                if let Some(dest) = dest_array(doc, value) {
                    names.insert(key, dest);
                }
            }
        }
    }
    if let Ok(kids) = node.get(b"Kids").and_then(|k| resolve_array(doc, k)) {
        for kid in kids {
            collect_name_tree(doc, &kid, names, depth + 1);
        }
    }
}

fn resolve_array(doc: &Document, object: &Object) -> lopdf::Result<Vec<Object>> {
    match object {
        Object::Array(a) => Ok(a.clone()),
        Object::Reference(id) => doc.get_object(*id)?.as_array().cloned(),
        _ => Err(lopdf::Error::ObjectType {
            expected: "Array",
            found: "other",
        }),
    }
}

fn rewrite_dests(object: &mut Object, names: &HashMap<Vec<u8>, Object>, depth: usize) {
    if depth > 24 {
        return;
    }
    match object {
        Object::Dictionary(dict) => rewrite_dict_dests(dict, names, depth),
        Object::Stream(stream) => rewrite_dict_dests(&mut stream.dict, names, depth),
        Object::Array(items) => {
            for item in items {
                rewrite_dests(item, names, depth + 1);
            }
        }
        _ => {}
    }
}

fn rewrite_dict_dests(dict: &mut Dictionary, names: &HashMap<Vec<u8>, Object>, depth: usize) {
    let lookup = |value: &Object| -> Option<Object> {
        let key = match value {
            Object::String(s, _) => s.as_slice(),
            Object::Name(n) => n.as_slice(),
            _ => return None,
        };
        names.get(key).cloned()
    };
    if let Some(dest) = dict.get(b"Dest").ok().and_then(lookup) {
        dict.set("Dest", dest);
    }
    let is_goto = dict
        .get(b"S")
        .and_then(Object::as_name)
        .map(|s| s == b"GoTo")
        .unwrap_or(false);
    if is_goto {
        if let Some(dest) = dict.get(b"D").ok().and_then(lookup) {
            dict.set("D", dest);
        }
    }
    for (_, value) in dict.iter_mut() {
        rewrite_dests(value, names, depth + 1);
    }
}

/// Create the merged outline. Returns the /Outlines object id, or None if there is nothing to show.
fn build_outlines(
    out: &mut Document,
    sections: &[Section],
    options: &MergeOptions,
) -> Option<ObjectId> {
    // Top-level entries: either one per file (with source outline nested) or, when
    // per-file bookmarks are off, the source outlines' own top-level items.
    let root_id = out.new_object_id();
    let mut top_items: Vec<ObjectId> = Vec::new();

    for section in sections {
        let source_children = section.outline_root.and_then(|root| {
            let root_dict = out.get_dictionary(root).ok()?.clone();
            let first = root_dict
                .get(b"First")
                .and_then(Object::as_reference)
                .ok()?;
            let last = root_dict.get(b"Last").and_then(Object::as_reference).ok()?;
            Some((first, last))
        });
        if let Some((first, last)) = source_children {
            prune_dead_outline_dests(out, first, &section.kept_pages, 0);
            // The source root itself is not needed any more.
            if let Some(root) = section.outline_root {
                out.objects.remove(&root);
            }
            if options.bookmarks {
                let item_id = out.add_object(dictionary! {
                    "Title" => text_string(&section.title),
                    "Dest" => vec![Object::Reference(section.first_page), "Fit".into()],
                    "First" => first,
                    "Last" => last,
                });
                reparent_siblings(out, first, item_id);
                top_items.push(item_id);
            } else {
                let mut cur = Some(first);
                let mut guard = 0;
                while let Some(id) = cur {
                    guard += 1;
                    if guard > 10_000 {
                        break;
                    }
                    top_items.push(id);
                    cur = out
                        .get_dictionary(id)
                        .ok()
                        .and_then(|d| d.get(b"Next").and_then(Object::as_reference).ok());
                }
            }
        } else if options.bookmarks {
            let item_id = out.add_object(dictionary! {
                "Title" => text_string(&section.title),
                "Dest" => vec![Object::Reference(section.first_page), "Fit".into()],
            });
            top_items.push(item_id);
        }
    }

    if top_items.is_empty() {
        return None;
    }

    // Link siblings and parents at the top level.
    for (i, &id) in top_items.iter().enumerate() {
        if let Ok(Object::Dictionary(item)) = out.get_object_mut(id) {
            item.set("Parent", root_id);
            if i > 0 {
                item.set("Prev", top_items[i - 1]);
            } else {
                item.remove(b"Prev");
            }
            if i + 1 < top_items.len() {
                item.set("Next", top_items[i + 1]);
            } else {
                item.remove(b"Next");
            }
        }
    }
    // Counts: file items are open; source items keep their own open/closed state.
    let mut total = 0;
    for &id in &top_items {
        fix_counts(out, id, 0);
        total += visible_count(out, id, 0);
    }
    out.objects.insert(
        root_id,
        Object::Dictionary(dictionary! {
            "Type" => "Outlines",
            "First" => top_items[0],
            "Last" => *top_items.last().unwrap(),
            "Count" => total,
        }),
    );
    Some(root_id)
}

fn reparent_siblings(out: &mut Document, first: ObjectId, parent: ObjectId) {
    let mut cur = Some(first);
    let mut guard = 0;
    while let Some(id) = cur {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        let next = match out.get_object_mut(id) {
            Ok(Object::Dictionary(item)) => {
                item.set("Parent", parent);
                item.get(b"Next").and_then(Object::as_reference).ok()
            }
            _ => None,
        };
        cur = next;
    }
}

/// Remove destinations that point at pages the user dropped, so the entries become inert
/// instead of broken. Walks siblings and children.
fn prune_dead_outline_dests(
    out: &mut Document,
    first: ObjectId,
    kept: &BTreeSet<ObjectId>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    let mut cur = Some(first);
    let mut guard = 0;
    while let Some(id) = cur {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        let (next, child) = {
            let Ok(Object::Dictionary(item)) = out.get_object_mut(id) else {
                break;
            };
            let target = item.get(b"Dest").ok().cloned().or_else(|| {
                item.get(b"A")
                    .ok()
                    .and_then(|a| a.as_dict().ok())
                    .and_then(|a| a.get(b"D").ok().cloned())
            });
            let target_page = target
                .as_ref()
                .and_then(|t| t.as_array().ok())
                .and_then(|a| a.first())
                .and_then(|p| p.as_reference().ok());
            if let Some(page) = target_page {
                if !kept.contains(&page) {
                    item.remove(b"Dest");
                    item.remove(b"A");
                }
            }
            (
                item.get(b"Next").and_then(Object::as_reference).ok(),
                item.get(b"First").and_then(Object::as_reference).ok(),
            )
        };
        if let Some(child) = child {
            prune_dead_outline_dests(out, child, kept, depth + 1);
        }
        cur = next;
    }
}

/// Make sure every item with children carries a /Count (positive: open).
fn fix_counts(out: &mut Document, id: ObjectId, depth: usize) {
    if depth > 32 {
        return;
    }
    let (first, has_count) = match out.get_dictionary(id) {
        Ok(d) => (
            d.get(b"First").and_then(Object::as_reference).ok(),
            d.has(b"Count"),
        ),
        Err(_) => return,
    };
    let Some(first) = first else { return };
    let mut children = Vec::new();
    let mut cur = Some(first);
    let mut guard = 0;
    while let Some(c) = cur {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        children.push(c);
        cur = out
            .get_dictionary(c)
            .ok()
            .and_then(|d| d.get(b"Next").and_then(Object::as_reference).ok());
    }
    for &c in &children {
        fix_counts(out, c, depth + 1);
    }
    if !has_count {
        let n: i64 = children
            .iter()
            .map(|&c| visible_count(out, c, depth + 1))
            .sum();
        if let Ok(Object::Dictionary(d)) = out.get_object_mut(id) {
            d.set("Count", n);
        }
    }
}

/// 1 for the item itself plus its descendants when it is open.
fn visible_count(out: &Document, id: ObjectId, depth: usize) -> i64 {
    if depth > 32 {
        return 1;
    }
    let Ok(d) = out.get_dictionary(id) else {
        return 1;
    };
    let open = d.get(b"Count").and_then(Object::as_i64).unwrap_or(0) > 0;
    let mut n = 1;
    if open {
        let mut cur = d.get(b"First").and_then(Object::as_reference).ok();
        let mut guard = 0;
        while let Some(c) = cur {
            guard += 1;
            if guard > 10_000 {
                break;
            }
            n += visible_count(out, c, depth + 1);
            cur = out
                .get_dictionary(c)
                .ok()
                .and_then(|x| x.get(b"Next").and_then(Object::as_reference).ok());
        }
    }
    n
}

// ---------------------------------------------------------------------------
// Interactive forms
// ---------------------------------------------------------------------------

fn build_acroform(out: &mut Document, sections: &[Section]) -> Option<ObjectId> {
    let mut fields: Vec<Object> = Vec::new();
    let mut used_names: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut resources = Dictionary::new();
    let mut default_appearance: Option<Object> = None;
    let mut quadding: Option<Object> = None;
    let mut need_appearances = false;

    for section in sections {
        let Some(form) = &section.acroform else {
            continue;
        };
        if form
            .get(b"NeedAppearances")
            .and_then(Object::as_bool)
            .unwrap_or(false)
        {
            need_appearances = true;
        }
        if default_appearance.is_none() {
            default_appearance = form.get(b"DA").ok().cloned();
        }
        if quadding.is_none() {
            quadding = form.get(b"Q").ok().cloned();
        }
        if let Some(dr) = form.get(b"DR").ok().and_then(|o| resolve_dict(out, o)) {
            merge_resource_dicts(&mut resources, &dr, out);
        }
        let Ok(list) = form.get(b"Fields").and_then(|f| resolve_array(out, f)) else {
            continue;
        };
        for field in list {
            let Ok(id) = field.as_reference() else {
                continue;
            };
            if !field_keeps_pages(out, id, &section.kept_pages, 0) {
                continue;
            }
            // Fields are identified by name; a repeated name would silently link them.
            if let Ok(Object::Dictionary(dict)) = out.get_object_mut(id) {
                if let Ok(Object::String(name, fmt)) = dict.get(b"T").cloned() {
                    let mut candidate = name.clone();
                    let mut n = 1;
                    while used_names.contains(&candidate) {
                        n += 1;
                        candidate = name.clone();
                        candidate.extend_from_slice(format!(" ({n})").as_bytes());
                    }
                    if candidate != name {
                        dict.set("T", Object::String(candidate.clone(), fmt));
                    }
                    used_names.insert(candidate);
                }
                // Signatures cannot survive a merge; the widget stays, the field type reverts to text-less.
                dict.remove(b"Lock");
            }
            fields.push(Object::Reference(id));
        }
    }
    if fields.is_empty() {
        return None;
    }
    let mut form = dictionary! { "Fields" => fields };
    if !resources.is_empty() {
        form.set("DR", Object::Dictionary(resources));
    }
    if let Some(da) = default_appearance {
        form.set("DA", da);
    }
    if let Some(q) = quadding {
        form.set("Q", q);
    }
    if need_appearances {
        form.set("NeedAppearances", true);
    }
    Some(out.add_object(form))
}

/// Merge /DR-style resource dictionaries: sub-dictionaries (Font, XObject, ...) are unioned,
/// first definition wins for a given name.
fn merge_resource_dicts(target: &mut Dictionary, extra: &Dictionary, doc: &Document) {
    for (key, value) in extra.iter() {
        let Some(sub) = resolve_dict(doc, value) else {
            if !target.has(key) {
                target.set(key.clone(), value.clone());
            }
            continue;
        };
        let mut merged = target
            .get(key)
            .ok()
            .and_then(|o| resolve_dict(doc, o))
            .unwrap_or_default();
        for (k, v) in sub.iter() {
            if !merged.has(k) {
                merged.set(k.clone(), v.clone());
            }
        }
        target.set(key.clone(), Object::Dictionary(merged));
    }
}

/// Keep a field if any of its widgets is on a kept page (or it has no page at all), pruning
/// kids that live on dropped pages.
fn field_keeps_pages(
    doc: &mut Document,
    id: ObjectId,
    kept: &BTreeSet<ObjectId>,
    depth: usize,
) -> bool {
    if depth > 32 {
        return true;
    }
    let (page, kids) = match doc.get_dictionary(id) {
        Ok(d) => (
            d.get(b"P").and_then(Object::as_reference).ok(),
            d.get(b"Kids").ok().and_then(|k| resolve_array(doc, k).ok()),
        ),
        Err(_) => return false,
    };
    match kids {
        Some(kids) => {
            let surviving: Vec<Object> = kids
                .into_iter()
                .filter(|k| {
                    k.as_reference()
                        .map(|kid| field_keeps_pages(doc, kid, kept, depth + 1))
                        .unwrap_or(false)
                })
                .collect();
            let any = !surviving.is_empty();
            if let Ok(Object::Dictionary(d)) = doc.get_object_mut(id) {
                d.set("Kids", surviving);
            }
            any || page.map(|p| kept.contains(&p)).unwrap_or(false)
        }
        None => page.map(|p| kept.contains(&p)).unwrap_or(true),
    }
}

// ---------------------------------------------------------------------------
// Optimisation
// ---------------------------------------------------------------------------

/// Point every reference to a duplicated stream (same dictionary and bytes) at one copy.
fn dedupe_streams(doc: &mut Document) {
    let mut groups: HashMap<u64, Vec<ObjectId>> = HashMap::new();
    for (&id, object) in &doc.objects {
        if let Object::Stream(stream) = object {
            if stream.dict.has(b"Type")
                && stream.dict.get(b"Type").and_then(Object::as_name).ok() == Some(b"XRef")
            {
                continue;
            }
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            let mut dict_bytes = Vec::new();
            write_dictionary(&stream.dict, &mut dict_bytes);
            dict_bytes.hash(&mut hasher);
            stream.content.hash(&mut hasher);
            groups.entry(hasher.finish()).or_default().push(id);
        }
    }
    let mut replace: HashMap<ObjectId, ObjectId> = HashMap::new();
    for ids in groups.values() {
        if ids.len() < 2 {
            continue;
        }
        let mut sorted = ids.clone();
        sorted.sort();
        let canonical = sorted[0];
        let Some(Object::Stream(base)) = doc.objects.get(&canonical) else {
            continue;
        };
        let (base_dict, base_content) = (base.dict.clone(), base.content.clone());
        for &other in &sorted[1..] {
            if let Some(Object::Stream(s)) = doc.objects.get(&other) {
                if s.dict == base_dict && s.content == base_content {
                    replace.insert(other, canonical);
                }
            }
        }
    }
    if replace.is_empty() {
        return;
    }
    for object in doc.objects.values_mut() {
        rewrite_refs(object, &replace, 0);
    }
    rewrite_refs_in_dict(&mut doc.trailer, &replace, 0);
}

fn rewrite_refs(object: &mut Object, map: &HashMap<ObjectId, ObjectId>, depth: usize) {
    if depth > 64 {
        return;
    }
    match object {
        Object::Reference(id) => {
            if let Some(&to) = map.get(id) {
                *id = to;
            }
        }
        Object::Array(items) => {
            for item in items {
                rewrite_refs(item, map, depth + 1);
            }
        }
        Object::Dictionary(dict) => rewrite_refs_in_dict(dict, map, depth),
        Object::Stream(stream) => rewrite_refs_in_dict(&mut stream.dict, map, depth),
        _ => {}
    }
}

fn rewrite_refs_in_dict(dict: &mut Dictionary, map: &HashMap<ObjectId, ObjectId>, depth: usize) {
    for (_, value) in dict.iter_mut() {
        rewrite_refs(value, map, depth + 1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use image::{ImageBuffer, ImageFormat, Rgb, Rgba};
    use std::io::Cursor;

    pub fn sample_pdf(pages: usize, text: &str) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        // Resources live on the Pages node so the inheritance path is exercised.
        let resources_id =
            doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let mut kids = Vec::new();
        for i in 0..pages {
            let content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 24.into()]),
                    Operation::new("Td", vec![72.into(), 700.into()]),
                    Operation::new(
                        "Tj",
                        vec![Object::string_literal(format!("{text} {}", i + 1))],
                    ),
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

    /// A PDF with a named destination, an outline pointing to it via name, a link annotation,
    /// and a text form field on each page.
    fn rich_pdf(pages: usize, field_prefix: &str) -> Vec<u8> {
        let base = sample_pdf(pages, "Rich");
        let mut doc = Document::load_mem(&base).unwrap();
        let page_ids: Vec<ObjectId> = doc.get_pages().into_values().collect();
        let catalog_id = doc
            .trailer
            .get(b"Root")
            .and_then(Object::as_reference)
            .unwrap();

        // Named destinations: "sec1" -> page 1, "secLast" -> last page.
        let dests_id = doc.add_object(dictionary! {
            "sec1" => vec![Object::Reference(page_ids[0]), "Fit".into()],
            "secLast" => vec![Object::Reference(*page_ids.last().unwrap()), "Fit".into()],
        });

        // Outline: two items referencing the named destinations.
        let outlines_id = doc.new_object_id();
        let item1 = doc.new_object_id();
        let item2 = doc.new_object_id();
        doc.objects.insert(
            item1,
            Object::Dictionary(dictionary! {
                "Title" => Object::string_literal("Section 1"), "Parent" => outlines_id,
                "Next" => item2, "Dest" => Object::string_literal("sec1"),
            }),
        );
        doc.objects.insert(
            item2,
            Object::Dictionary(dictionary! {
                "Title" => Object::string_literal("Last section"), "Parent" => outlines_id, "Prev" => item1,
                "A" => dictionary! { "S" => "GoTo", "D" => Object::string_literal("secLast") },
            }),
        );
        doc.objects.insert(
            outlines_id,
            Object::Dictionary(dictionary! {
                "Type" => "Outlines", "First" => item1, "Last" => item2, "Count" => 2,
            }),
        );

        // One text field per page, widget merged with field.
        let mut fields = Vec::new();
        for (i, &pid) in page_ids.iter().enumerate() {
            let field_id = doc.add_object(dictionary! {
                "FT" => "Tx", "T" => Object::string_literal(format!("{field_prefix}{}", i + 1)),
                "Type" => "Annot", "Subtype" => "Widget", "P" => pid,
                "Rect" => vec![72.into(), 72.into(), 300.into(), 100.into()],
                "V" => Object::string_literal("value"),
            });
            if let Ok(Object::Dictionary(page)) = doc.get_object_mut(pid) {
                page.set("Annots", vec![Object::Reference(field_id)]);
            }
            fields.push(Object::Reference(field_id));
        }
        let acroform_id = doc.add_object(dictionary! {
            "Fields" => fields, "DA" => Object::string_literal("/Helv 0 Tf 0 g"),
            "DR" => dictionary! { "Font" => dictionary! { "Helv" => dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica" } } },
        });

        if let Ok(Object::Dictionary(cat)) = doc.get_object_mut(catalog_id) {
            cat.set("Dests", dests_id);
            cat.set("Outlines", outlines_id);
            cat.set("AcroForm", acroform_id);
        }
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    pub fn sample_png(w: u32, h: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(w, h, |x, y| {
            Rgba([x as u8, y as u8, 128u8, if x % 2 == 0 { 255 } else { 0 }])
        });
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
        MergeInput::new(name, data)
    }

    fn page_count(pdf: &[u8]) -> usize {
        Document::load_mem(pdf).unwrap().get_pages().len()
    }

    fn page_text(doc: &Document, page: ObjectId) -> String {
        String::from_utf8_lossy(&doc.get_page_content(page)).into_owned()
    }

    fn opts() -> MergeOptions {
        MergeOptions::default()
    }

    /// Every place a secret was planted, searched in the output with all streams
    /// decompressed, so a compressed leftover cannot hide from the check.
    fn planted_secrets_in(pdf: &[u8]) -> Vec<String> {
        let mut doc = Document::load_mem(pdf).unwrap();
        doc.decompress();
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        let secrets: [&[u8]; 5] = [
            b"PAGEXMPSECRET",
            b"PIECEINFOSECRET",
            b"LastModified",
            b"FixtureArtist",
            b"FixtureComment",
        ];
        secrets
            .iter()
            .filter(|s| bytes.windows(s.len()).any(|w| w == **s))
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect()
    }

    /// A one-page PDF shaped like a phone scanner's output: the page carries an XMP
    /// packet, application data and an edit time, and its image is a JPEG straight
    /// from the camera, EXIF and GPS position included.
    fn scanner_style_pdf(photo: &[u8]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let xmp = doc.add_object(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<x:xmpmeta>PAGEXMPSECRET</x:xmpmeta>".to_vec(),
        ));
        let image = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image", "Width" => 48, "Height" => 32,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "Filter" => "DCTDecode",
            },
            photo.to_vec(),
        ));
        let content = doc.add_object(Stream::new(
            dictionary! {},
            b"q 48 0 0 32 0 0 cm /Im0 Do Q".to_vec(),
        ));
        let page = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 48.into(), 32.into()],
            "Contents" => content,
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => image } },
            "Metadata" => xmp,
            "PieceInfo" => dictionary! {
                "Scanner" => dictionary! { "Private" => Object::string_literal("PIECEINFOSECRET") },
            },
            "LastModified" => Object::string_literal("D:20260101000000Z"),
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(
                dictionary! { "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1 },
            ),
        );
        let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    #[test]
    fn output_password_encrypts_with_aes256_and_round_trips() {
        let inputs = [
            input("a.pdf", sample_pdf(2, "Statement")),
            input("b.png", sample_png(40, 30)),
        ];
        // A non-ASCII password exercises the SASLprep step revision 6 requires.
        let password = "Café-løcked 42";
        // Uncompressed, so the page text would sit in the file in the clear if the
        // encryption did not cover it.
        let uncompressed = MergeOptions {
            optimize: false,
            ..opts()
        };
        let plain = merge(&inputs, &uncompressed).unwrap();
        assert!(String::from_utf8_lossy(&plain).contains("Statement"));
        assert!(!String::from_utf8_lossy(&plain).contains("/Encrypt"));
        let pdf = merge(
            &inputs,
            &MergeOptions {
                output_password: Some(password.to_string()),
                ..uncompressed
            },
        )
        .unwrap();

        // AES-256 (V5, revision 6), and nothing readable in the clear.
        let text = String::from_utf8_lossy(&pdf).into_owned();
        assert!(text.contains("/Encrypt"));
        assert!(text.contains("/AESV3"));
        assert!(text.contains("/R 6"));
        assert!(!text.contains("Statement"));

        // The app's own loader: refused without the password, refused with a wrong one,
        // opened with the right one, with every page intact.
        let mut reopen = MergeInput::new("out.pdf", pdf.clone());
        assert!(matches!(
            load_pdf(&reopen),
            Err(MergeError::Encrypted { .. })
        ));
        reopen.password = Some("wrong".into());
        assert!(matches!(
            load_pdf(&reopen),
            Err(MergeError::WrongPassword { .. })
        ));
        reopen.password = Some(password.to_string());
        let (doc, was_encrypted) = load_pdf(&reopen).unwrap();
        assert!(was_encrypted);
        assert_eq!(doc.get_pages().len(), 3);
        let first = *doc.get_pages().get(&1).unwrap();
        let content = String::from_utf8_lossy(&doc.get_page_content(first)).into_owned();
        assert!(content.contains("Statement"), "{content}");
    }

    #[test]
    fn hidden_metadata_is_stripped_unless_asked_to_keep() {
        let photo = include_bytes!("../tests/fixtures/progressive_rst.jpg");
        let inputs = [
            input("scan.pdf", scanner_style_pdf(photo)),
            input("photo.jpg", photo.to_vec()),
        ];

        let clean = merge(&inputs, &opts()).unwrap();
        assert_eq!(planted_secrets_in(&clean), Vec::<String>::new());
        // Nothing visible was lost: both pages are there and both photos still decode
        // to the same pixels as the original.
        let doc = Document::load_mem(&clean).unwrap();
        assert_eq!(doc.get_pages().len(), 2);
        let original = image::load_from_memory(photo).unwrap().to_rgb8();
        let jpegs: Vec<_> = doc
            .objects
            .values()
            .filter_map(|o| o.as_stream().ok())
            .filter(|s| is_plain_jpeg(&s.dict))
            .collect();
        assert!(!jpegs.is_empty());
        for stream in jpegs {
            let decoded = image::load_from_memory(&stream.content).unwrap().to_rgb8();
            assert_eq!(decoded.as_raw(), original.as_raw());
        }

        // The switch really is what removes them: kept on request.
        let kept = merge(
            &inputs,
            &MergeOptions {
                strip_metadata: false,
                ..opts()
            },
        )
        .unwrap();
        assert_eq!(
            planted_secrets_in(&kept),
            [
                "PAGEXMPSECRET",
                "PIECEINFOSECRET",
                "LastModified",
                "FixtureArtist",
                "FixtureComment"
            ]
        );
    }

    #[test]
    fn merges_pdfs_in_order_and_keeps_inherited_attributes() {
        let merged = merge(
            &[
                input("a.pdf", sample_pdf(2, "A")),
                input("b.pdf", sample_pdf(3, "B")),
            ],
            &opts(),
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 5);
        for page_id in pages.values() {
            let page = doc.get_dictionary(*page_id).unwrap();
            assert!(
                page.has(b"MediaBox"),
                "MediaBox must be copied down from the Pages node"
            );
            assert!(
                page.has(b"Resources"),
                "Resources must be copied down from the Pages node"
            );
        }
        assert!(page_text(&doc, pages[&1]).contains("A 1"));
        assert!(page_text(&doc, pages[&5]).contains("B 3"));
    }

    #[test]
    fn page_selection_and_rotation() {
        let mut a = input("a.pdf", sample_pdf(5, "A"));
        a.pages = Some(vec![5, 1, 1]);
        a.rotate = 90;
        a.page_rotations.insert(1, 180);
        let merged = merge(&[a], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 3);
        assert!(page_text(&doc, pages[&1]).contains("A 5"));
        assert!(page_text(&doc, pages[&2]).contains("A 1"));
        assert!(page_text(&doc, pages[&3]).contains("A 1"));
        assert_ne!(
            pages[&2], pages[&3],
            "a page used twice must be two objects"
        );
        let rot = |n: u32| {
            doc.get_dictionary(pages[&n])
                .unwrap()
                .get(b"Rotate")
                .and_then(Object::as_i64)
                .unwrap()
        };
        assert_eq!(rot(1), 90);
        assert_eq!(rot(2), 270);
        assert_eq!(rot(3), 270);
        assert_eq!(page_size_pt(&doc, pages[&1]), (792.0, 612.0));
    }

    #[test]
    fn page_spec_strings_are_resolved() {
        let mut a = input("a.pdf", sample_pdf(6, "A"));
        a.page_spec = Some("even,1".into());
        let merged = merge(&[a], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 4);
        assert!(page_text(&doc, pages[&1]).contains("A 2"));
        assert!(page_text(&doc, pages[&4]).contains("A 1"));
        let mut bad = input("a.pdf", sample_pdf(2, "A"));
        bad.page_spec = Some("7".into());
        assert!(matches!(
            merge(&[bad], &opts()),
            Err(MergeError::PageSelection { .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_selection() {
        let mut a = input("a.pdf", sample_pdf(2, "A"));
        a.pages = Some(vec![3]);
        assert!(matches!(
            merge(&[a], &opts()),
            Err(MergeError::PageSelection { .. })
        ));
    }

    #[test]
    fn merges_images_and_pdfs_together() {
        let merged = merge(
            &[
                input("scan.jpg", sample_jpeg(40, 30)),
                input("doc.pdf", sample_pdf(1, "D")),
                input("shot.png", sample_png(20, 50)),
            ],
            &MergeOptions {
                page_size: PageSize::A4,
                margin_pt: 18.0,
                ..opts()
            },
        )
        .unwrap();
        assert_eq!(page_count(&merged), 3);
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert!(
            page_size_pt(&doc, pages[&1]).0 > page_size_pt(&doc, pages[&1]).1,
            "landscape JPEG -> landscape A4"
        );
        assert!(
            page_size_pt(&doc, pages[&3]).0 < page_size_pt(&doc, pages[&3]).1,
            "portrait PNG -> portrait A4"
        );
    }

    #[test]
    fn jpeg_is_passed_through_without_reencoding() {
        let jpeg = sample_jpeg(16, 16);
        let merged = merge(&[input("x.jpg", jpeg.clone())], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let has_dct = doc.objects.values().any(|o| {
            o.as_stream()
                .map(|s| {
                    s.dict.get(b"Filter").and_then(Object::as_name).ok()
                        == Some(b"DCTDecode".as_slice())
                        && s.content == jpeg
                })
                .unwrap_or(false)
        });
        assert!(has_dct);
    }

    #[test]
    fn fit_page_uses_dpi_when_present() {
        // No DPI: 1 px = 1 pt.
        let merged = merge(&[input("p.png", sample_png(120, 80))], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        assert_eq!(page_size_pt(&doc, doc.get_pages()[&1]), (120.0, 80.0));
        // With DPI (JFIF 300 dpi): 300 px = 1 inch = 72 pt.
        let mut jpeg = sample_jpeg(300, 150);
        let app0 = [
            0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 1, 0x01, 0x2C, 0x01, 0x2C, 0,
            0,
        ];
        jpeg.splice(2..2, app0);
        let merged = merge(&[input("s.jpg", jpeg.clone())], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let (w, h) = page_size_pt(&doc, doc.get_pages()[&1]);
        assert!(
            (w - 72.0).abs() < 0.5 && (h - 36.0).abs() < 0.5,
            "got {w}x{h}"
        );
        // DPI ignored on request.
        let merged = merge(
            &[input("s.jpg", jpeg)],
            &MergeOptions {
                use_image_dpi: false,
                ..opts()
            },
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        assert_eq!(page_size_pt(&doc, doc.get_pages()[&1]), (300.0, 150.0));
    }

    #[test]
    fn multipage_tiff_and_svg_become_pages() {
        use tiff::encoder::{colortype, TiffEncoder};
        let mut buf = Cursor::new(Vec::new());
        {
            let mut enc = TiffEncoder::new(&mut buf).unwrap();
            for shade in [10u8, 200u8, 90u8] {
                enc.write_image::<colortype::Gray8>(6, 4, &[shade; 24])
                    .unwrap();
            }
        }
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96"><circle cx="48" cy="48" r="40" fill="blue"/></svg>"#.to_vec();
        let mut tif = input("scan.tif", buf.into_inner());
        tif.pages = Some(vec![3, 1]);
        let merged = merge(&[tif, input("logo.svg", svg)], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        assert_eq!(doc.get_pages().len(), 3);
        let (w, h) = page_size_pt(&doc, doc.get_pages()[&3]);
        assert!(
            (w - 72.0).abs() < 1.0 && (h - 72.0).abs() < 1.0,
            "svg page should be 1in: {w}x{h}"
        );
    }

    #[test]
    fn merging_the_output_again_works() {
        let once = merge(
            &[
                input("a.pdf", sample_pdf(2, "A")),
                input("i.png", sample_png(8, 8)),
            ],
            &opts(),
        )
        .unwrap();
        let twice = merge(
            &[input("once.pdf", once.clone()), input("once2.pdf", once)],
            &opts(),
        )
        .unwrap();
        assert_eq!(page_count(&twice), 6);
    }

    #[test]
    fn rejects_garbage_and_empty_input() {
        assert!(matches!(merge(&[], &opts()), Err(MergeError::NoInputs)));
        let err = merge(&[input("notes.txt", b"hello".to_vec())], &opts()).unwrap_err();
        assert!(matches!(err, MergeError::Unsupported { .. }));
        let err = merge(&[input("bad.pdf", b"%PDF-1.4 garbage".to_vec())], &opts()).unwrap_err();
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
        let locked = aes256_encrypted(&sample_pdf(2, "Locked"), "");
        let merged = merge(
            &[
                input("locked.pdf", locked),
                input("plain.pdf", sample_pdf(1, "Plain")),
            ],
            &opts(),
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 3);
        assert!(doc.trailer.get(b"Encrypt").is_err());
        assert!(page_text(&doc, pages[&2]).contains("Locked 2"));
        assert!(page_text(&doc, pages[&3]).contains("Plain 1"));
    }

    #[test]
    fn user_locked_pdf_needs_the_right_password() {
        let locked = aes256_encrypted(&sample_pdf(1, "Secret"), "user-pw");
        let err = merge(&[input("secret.pdf", locked.clone())], &opts()).unwrap_err();
        assert!(matches!(err, MergeError::Encrypted { .. }), "got {err:?}");
        let mut wrong = input("secret.pdf", locked.clone());
        wrong.password = Some("nope".into());
        assert!(matches!(
            merge(&[wrong], &opts()),
            Err(MergeError::WrongPassword { .. })
        ));
        let mut right = input("secret.pdf", locked);
        right.password = Some("user-pw".into());
        let merged = merge(&[right], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        assert!(page_text(&doc, doc.get_pages()[&1]).contains("Secret 1"));
    }

    #[test]
    fn direct_encrypt_dictionary_fixtures() {
        let owner_locked = include_bytes!("../tests/fixtures/owner_locked.pdf");
        let user_locked = include_bytes!("../tests/fixtures/user_locked.pdf");
        let merged = merge(&[input("owner_locked.pdf", owner_locked.to_vec())], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 2);
        let content = page_text(&doc, pages[&1]);
        assert!(
            content.contains("BT") && content.contains("Tf"),
            "content stream should be readable, got {content:?}"
        );
        let err = merge(&[input("user_locked.pdf", user_locked.to_vec())], &opts()).unwrap_err();
        assert!(matches!(err, MergeError::Encrypted { .. }), "got {err:?}");
        let mut right = input("user_locked.pdf", user_locked.to_vec());
        right.password = Some("pw".into());
        assert_eq!(page_count(&merge(&[right], &opts()).unwrap()), 1);
    }

    #[test]
    fn outline_has_file_bookmarks_with_nested_source_outline_and_resolved_names() {
        let merged = merge(
            &[
                input("Report Q1.pdf", rich_pdf(3, "f")),
                input("plain.pdf", sample_pdf(1, "P")),
            ],
            &opts(),
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let pages = doc.get_pages();
        let catalog = doc
            .get_dictionary(
                doc.trailer
                    .get(b"Root")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let outlines = doc
            .get_dictionary(
                catalog
                    .get(b"Outlines")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let first = doc
            .get_dictionary(
                outlines
                    .get(b"First")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(first.get(b"Title").unwrap().as_str().unwrap(), b"Report Q1");
        let dest = first.get(b"Dest").unwrap().as_array().unwrap();
        assert_eq!(dest[0].as_reference().unwrap(), pages[&1]);
        // Nested source items with names resolved to explicit destinations.
        let child = doc
            .get_dictionary(first.get(b"First").and_then(Object::as_reference).unwrap())
            .unwrap();
        assert_eq!(child.get(b"Title").unwrap().as_str().unwrap(), b"Section 1");
        assert_eq!(
            child.get(b"Dest").unwrap().as_array().unwrap()[0]
                .as_reference()
                .unwrap(),
            pages[&1]
        );
        let child2 = doc
            .get_dictionary(child.get(b"Next").and_then(Object::as_reference).unwrap())
            .unwrap();
        let action = child2.get(b"A").unwrap().as_dict().unwrap();
        assert_eq!(
            action.get(b"D").unwrap().as_array().unwrap()[0]
                .as_reference()
                .unwrap(),
            pages[&3]
        );
        // Second file bookmark.
        let second = doc
            .get_dictionary(first.get(b"Next").and_then(Object::as_reference).unwrap())
            .unwrap();
        assert_eq!(second.get(b"Title").unwrap().as_str().unwrap(), b"plain");
        assert_eq!(
            second.get(b"Dest").unwrap().as_array().unwrap()[0]
                .as_reference()
                .unwrap(),
            pages[&4]
        );
        assert_eq!(outlines.get(b"Count").and_then(Object::as_i64).unwrap(), 4);
    }

    #[test]
    fn outline_entries_to_dropped_pages_become_inert() {
        let mut a = input("r.pdf", rich_pdf(3, "f"));
        a.pages = Some(vec![1, 2]);
        let merged = merge(
            &[a],
            &MergeOptions {
                bookmarks: false,
                ..opts()
            },
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let catalog = doc
            .get_dictionary(
                doc.trailer
                    .get(b"Root")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let outlines = doc
            .get_dictionary(
                catalog
                    .get(b"Outlines")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let first = doc
            .get_dictionary(
                outlines
                    .get(b"First")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(first.get(b"Title").unwrap().as_str().unwrap(), b"Section 1");
        assert!(first.has(b"Dest"));
        let last = doc
            .get_dictionary(first.get(b"Next").and_then(Object::as_reference).unwrap())
            .unwrap();
        assert!(
            !last.has(b"A") && !last.has(b"Dest"),
            "entry to the dropped page 3 must lose its target"
        );
    }

    #[test]
    fn forms_are_merged_and_colliding_names_renamed() {
        let merged = merge(
            &[
                input("a.pdf", rich_pdf(2, "name")),
                input("b.pdf", rich_pdf(2, "name")),
            ],
            &opts(),
        )
        .unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let catalog = doc
            .get_dictionary(
                doc.trailer
                    .get(b"Root")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let form = doc
            .get_dictionary(
                catalog
                    .get(b"AcroForm")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let fields = form.get(b"Fields").unwrap().as_array().unwrap();
        assert_eq!(fields.len(), 4);
        let names: Vec<String> = fields
            .iter()
            .map(|f| {
                String::from_utf8_lossy(
                    doc.get_dictionary(f.as_reference().unwrap())
                        .unwrap()
                        .get(b"T")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                )
                .into_owned()
            })
            .collect();
        assert_eq!(names, vec!["name1", "name2", "name1 (2)", "name2 (2)"]);
        assert!(form.has(b"DA"));
        assert!(form
            .get(b"DR")
            .unwrap()
            .as_dict()
            .unwrap()
            .get(b"Font")
            .unwrap()
            .as_dict()
            .unwrap()
            .has(b"Helv"));
    }

    #[test]
    fn fields_on_dropped_pages_are_removed() {
        let mut a = input("a.pdf", rich_pdf(3, "f"));
        a.pages = Some(vec![2]);
        let merged = merge(&[a], &opts()).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let catalog = doc
            .get_dictionary(
                doc.trailer
                    .get(b"Root")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let form = doc
            .get_dictionary(
                catalog
                    .get(b"AcroForm")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        let fields = form.get(b"Fields").unwrap().as_array().unwrap();
        assert_eq!(fields.len(), 1);
        let t = doc
            .get_dictionary(fields[0].as_reference().unwrap())
            .unwrap()
            .get(b"T")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(t, b"f2");
    }

    #[test]
    fn duplicate_streams_are_shared_once() {
        let jpeg = sample_jpeg(32, 32);
        let unoptimised = merge(
            &[
                input("a.jpg", jpeg.clone()),
                input("b.jpg", jpeg.clone()),
                input("c.jpg", jpeg.clone()),
            ],
            &MergeOptions {
                optimize: false,
                ..opts()
            },
        )
        .unwrap();
        let optimised = merge(
            &[
                input("a.jpg", jpeg.clone()),
                input("b.jpg", jpeg.clone()),
                input("c.jpg", jpeg.clone()),
            ],
            &opts(),
        )
        .unwrap();
        let count_dct = |pdf: &[u8]| {
            Document::load_mem(pdf)
                .unwrap()
                .objects
                .values()
                .filter(|o| {
                    o.as_stream()
                        .map(|s| {
                            s.dict.get(b"Filter").and_then(Object::as_name).ok()
                                == Some(b"DCTDecode".as_slice())
                        })
                        .unwrap_or(false)
                })
                .count()
        };
        assert_eq!(count_dct(&unoptimised), 3);
        assert_eq!(count_dct(&optimised), 1);
        assert!(optimised.len() < unoptimised.len());
        assert_eq!(page_count(&optimised), 3);
    }

    #[test]
    fn metadata_is_written() {
        let options = MergeOptions {
            metadata: Metadata {
                title: Some("Bündel".into()),
                author: Some("Ana".into()),
                subject: None,
                keywords: Some(" ".into()),
            },
            ..opts()
        };
        let merged = merge(&[input("a.pdf", sample_pdf(1, "A"))], &options).unwrap();
        let doc = Document::load_mem(&merged).unwrap();
        let info = doc
            .get_dictionary(
                doc.trailer
                    .get(b"Info")
                    .and_then(Object::as_reference)
                    .unwrap(),
            )
            .unwrap();
        assert!(info
            .get(b"Title")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&[0xFE, 0xFF]));
        assert_eq!(info.get(b"Author").unwrap().as_str().unwrap(), b"Ana");
        assert!(!info.has(b"Subject") && !info.has(b"Keywords"));
    }

    #[test]
    fn progress_is_reported() {
        let mut seen = Vec::new();
        merge_with_progress(
            &[
                input("a.pdf", sample_pdf(1, "A")),
                input("b.pdf", sample_pdf(1, "B")),
            ],
            &opts(),
            |p| seen.push((p.step, p.total, p.label)),
        )
        .unwrap();
        assert_eq!(seen.len(), 5);
        assert_eq!(seen[0].0, 0);
        assert!(seen[0].2.contains("a.pdf"));
        assert_eq!(seen.last().unwrap().0, 4);
        assert!(seen.iter().all(|(_, total, _)| *total == 5));
    }

    #[test]
    fn detects_kinds() {
        assert_eq!(
            detect_kind("x.bin", &sample_png(2, 2)),
            Some(InputKind::Image)
        );
        assert_eq!(
            detect_kind("x.bin", &sample_pdf(1, "x")),
            Some(InputKind::Pdf)
        );
        assert_eq!(detect_kind("photo.JPG", b""), Some(InputKind::Image));
        assert_eq!(detect_kind("logo.svg", b"<svg/>"), Some(InputKind::Image));
        assert_eq!(detect_kind("readme.md", b"# hi"), None);
        assert!(is_supported_name("Scan 001.TIFF"));
        assert!(!is_supported_name("archive.zip"));
        assert_eq!(display_title("dir/Report Q1.final.pdf"), "Report Q1.final");
        assert_eq!(display_title("C:\\scans\\x.PNG"), "x");
    }
}
