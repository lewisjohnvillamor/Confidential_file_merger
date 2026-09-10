//! Cryptographic PDF signatures (PKCS#7 / CMS, `adbe.pkcs7.detached`) and verification.
//!
//! Signing appends an incremental update to the file: a signature dictionary with a
//! `/ByteRange` covering everything except the signature bytes themselves, a signature
//! field (optionally with a visible appearance), and the CMS blob. Earlier bytes are left
//! untouched, so signatures already present in the file stay valid and several people
//! can sign one document in turn.
//!
//! Everything is computed locally; no timestamp authority or revocation service is
//! contacted.

use std::time::{SystemTime, UNIX_EPOCH};

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::{OctetString, SetOfVec, UtcTime};
use der::{Any, Decode, Encode, EncodePem};
use lopdf::{dictionary, Document, IncrementalDocument, Object, ObjectId, Stream, StringFormat};
use serde::Serialize;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

use crate::certs::{self, CertInfo, PrivateKey, Signer};
use crate::merge::{self, MergeError, MergeInput};
use crate::sign::Placement;

/// Room reserved for the CMS blob (hex-encoded in the file). Plenty for one certificate.
const CONTENTS_BYTES: usize = 8192;

#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
    /// Where to draw the visible signature box, if any (page-fraction geometry). The image,
    /// when given, is drawn inside the box together with the signer's name and the date.
    pub visible: Option<VisibleSignature>,
}

#[derive(Debug, Clone)]
pub struct VisibleSignature {
    pub placement: Placement,
    pub image_png: Option<Vec<u8>>,
}

fn pdf_err(name: &str, message: impl Into<String>) -> MergeError {
    MergeError::Pdf {
        name: name.to_string(),
        source: lopdf::Error::InvalidStream(message.into()),
    }
}

/// Sign `input` with `signer`. The input may already carry signatures; they are preserved.
pub fn sign_pdf(
    input: &MergeInput,
    signer: &Signer,
    options: &SignOptions,
) -> Result<Vec<u8>, MergeError> {
    // Work on plain bytes: an encrypted file is rewritten unencrypted first, which is the
    // only case where earlier signatures cannot be preserved.
    let (doc, was_encrypted) = merge::load_pdf(input)?;
    let base_bytes = if was_encrypted {
        let mut doc = doc;
        doc.encryption_state = None;
        let mut buf = Vec::new();
        doc.save_to(&mut buf).map_err(MergeError::Write)?;
        buf
    } else {
        input.data.clone()
    };
    let doc = Document::load_mem(&base_bytes).map_err(|e| MergeError::Pdf {
        name: input.name.clone(),
        source: e,
    })?;
    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(MergeError::NoPages {
            name: input.name.clone(),
        });
    }
    let existing_signatures = count_signature_fields(&doc);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut inc = IncrementalDocument::create_from(base_bytes.clone(), doc);

    // --- signature dictionary with placeholders -------------------------------------
    let mut sig_dict = dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "adbe.pkcs7.detached",
        "ByteRange" => vec![0.into(), 999_999_999_999i64.into(), 999_999_999_999i64.into(), 999_999_999_999i64.into()],
        "Contents" => Object::String(vec![0u8; CONTENTS_BYTES], StringFormat::Hexadecimal),
        "M" => Object::string_literal(certs::pdf_date(now.as_secs())),
        "Name" => text(&signer.info.common_name),
    };
    if let Some(reason) = options
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sig_dict.set("Reason", text(reason));
    }
    if let Some(location) = options
        .location
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sig_dict.set("Location", text(location));
    }
    if let Some(contact) = options
        .contact
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sig_dict.set("ContactInfo", text(contact));
    }
    let sig_id = inc.new_document.add_object(sig_dict);

    // --- widget / field ---------------------------------------------------------------
    let field_name = format!("Signature{}", existing_signatures + 1);
    let (page_no, rect, appearance) = match &options.visible {
        Some(visible) => {
            let page_no = visible.placement.page;
            if page_no == 0 || page_no as usize > pages.len() {
                return Err(MergeError::PageSelection {
                    name: input.name.clone(),
                    message: format!("page {page_no} does not exist"),
                });
            }
            let page_id = pages[&page_no];
            let geometry = crate::sign::page_geometry(inc.get_prev_documents(), page_id);
            let rect = crate::sign::placement_rect(&geometry, &visible.placement);
            let ap = build_appearance(
                &mut inc.new_document,
                &rect,
                visible,
                signer,
                now.as_secs(),
                options,
            )?;
            (page_no, rect, Some(ap))
        }
        None => (1, [0.0, 0.0, 0.0, 0.0], None),
    };
    let page_id = pages[&page_no];
    let mut widget = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Sig",
        "T" => text(&field_name),
        "V" => sig_id,
        "P" => page_id,
        "F" => 132i64, // print + locked
        "Rect" => vec![rect[0].into(), rect[1].into(), rect[2].into(), rect[3].into()],
    };
    if let Some(ap_id) = appearance {
        widget.set("AP", dictionary! { "N" => ap_id });
    }
    let widget_id = inc.new_document.add_object(widget);

    // Page: append the widget to /Annots.
    inc.opt_clone_object_to_new_document(page_id)
        .map_err(|e| pdf_err(&input.name, e.to_string()))?;
    let existing_annots: Vec<Object> = match inc
        .new_document
        .get_dictionary(page_id)
        .ok()
        .and_then(|p| p.get(b"Annots").ok().cloned())
    {
        Some(Object::Array(items)) => items,
        Some(Object::Reference(id)) => match inc.get_prev_documents().get_object(id) {
            Ok(Object::Array(items)) => items.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    let mut annots = existing_annots;
    annots.push(Object::Reference(widget_id));
    if let Ok(Object::Dictionary(page)) = inc.new_document.get_object_mut(page_id) {
        page.set("Annots", Object::Array(annots));
    }

    // Catalog: /AcroForm with the field added and SigFlags set.
    let catalog_id = inc
        .get_prev_documents()
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|e| pdf_err(&input.name, e.to_string()))?;
    inc.opt_clone_object_to_new_document(catalog_id)
        .map_err(|e| pdf_err(&input.name, e.to_string()))?;
    let prev = inc.get_prev_documents();
    let mut acroform = prev
        .get_dictionary(catalog_id)
        .ok()
        .and_then(|c| c.get(b"AcroForm").ok().cloned())
        .and_then(|a| match a {
            Object::Dictionary(d) => Some(d),
            Object::Reference(id) => prev.get_dictionary(id).ok().cloned(),
            _ => None,
        })
        .unwrap_or_default();
    let mut fields: Vec<Object> = match acroform.get(b"Fields").ok().cloned() {
        Some(Object::Array(items)) => items,
        Some(Object::Reference(id)) => match prev.get_object(id) {
            Ok(Object::Array(items)) => items.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    fields.push(Object::Reference(widget_id));
    acroform.set("Fields", Object::Array(fields));
    acroform.set("SigFlags", 3i64);
    if let Ok(Object::Dictionary(catalog)) = inc.new_document.get_object_mut(catalog_id) {
        catalog.set("AcroForm", Object::Dictionary(acroform));
    }

    // --- write the update, then patch ByteRange and Contents in place -----------------
    let mut bytes = Vec::new();
    inc.save_to(&mut bytes).map_err(MergeError::Write)?;
    // Only search the appended part so earlier signatures' placeholders are never touched.
    let tail_start = base_bytes.len();
    // The placeholder is a hex string of zeros of a size nothing else in the file has.
    let mut needle = Vec::with_capacity(CONTENTS_BYTES * 2 + 2);
    needle.push(b'<');
    needle.resize(CONTENTS_BYTES * 2 + 1, b'0');
    needle.push(b'>');
    let contents_start = find_from(&bytes, tail_start, &needle)
        .ok_or_else(|| pdf_err(&input.name, "signature placeholder not found"))?;
    let contents_end = contents_start + needle.len();
    let br_open = find_from(&bytes, tail_start, b"/ByteRange")
        .and_then(|p| find_from(&bytes, p, b"["))
        .ok_or_else(|| pdf_err(&input.name, "byte range placeholder not found"))?;
    let br_close = find_from(&bytes, br_open, b"]")
        .ok_or_else(|| pdf_err(&input.name, "byte range not terminated"))?;
    let range = [
        0usize,
        contents_start,
        contents_end,
        bytes.len() - contents_end,
    ];
    let mut br_text = format!("[{} {} {} {}", range[0], range[1], range[2], range[3]);
    let room = br_close - br_open;
    if br_text.len() > room {
        return Err(pdf_err(&input.name, "byte range does not fit"));
    }
    while br_text.len() < room {
        br_text.push(' ');
    }
    bytes[br_open..br_close].copy_from_slice(br_text.as_bytes());

    // --- digest the covered ranges and build the CMS signature -----------------------
    let mut hasher = Sha256::new();
    hasher.update(&bytes[range[0]..range[0] + range[1]]);
    hasher.update(&bytes[range[2]..range[2] + range[3]]);
    let digest = hasher.finalize();
    let cms_der = build_cms(signer, &digest, now.as_secs()).map_err(|e| pdf_err(&input.name, e))?;
    if cms_der.len() > CONTENTS_BYTES {
        return Err(pdf_err(
            &input.name,
            "signature is larger than the reserved space",
        ));
    }
    let mut hex = String::with_capacity(CONTENTS_BYTES * 2);
    for b in &cms_der {
        hex.push_str(&format!("{b:02x}"));
    }
    while hex.len() < CONTENTS_BYTES * 2 {
        hex.push('0');
    }
    bytes[contents_start + 1..contents_end - 1].copy_from_slice(hex.as_bytes());
    Ok(bytes)
}

fn text(s: &str) -> Object {
    if s.is_ascii() {
        Object::string_literal(s)
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for unit in s.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Object::String(bytes, StringFormat::Literal)
    }
}

fn find_from(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn count_signature_fields(doc: &Document) -> usize {
    doc.objects
        .values()
        .filter(|o| {
            o.as_dict()
                .map(|d| {
                    d.get(b"FT")
                        .and_then(Object::as_name)
                        .map(|n| n == b"Sig")
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        })
        .count()
}

/// Appearance stream: the signature image (if any) on the left, name and date on the right.
fn build_appearance(
    doc: &mut Document,
    rect: &[f64; 4],
    visible: &VisibleSignature,
    signer: &Signer,
    now_secs: u64,
    options: &SignOptions,
) -> Result<ObjectId, MergeError> {
    let w = (rect[2] - rect[0]).abs().max(1.0);
    let h = (rect[3] - rect[1]).abs().max(1.0);
    let mut resources = dictionary! {
        "Font" => dictionary! {
            "Helv" => dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica", "Encoding" => "WinAnsiEncoding" },
        },
    };
    let mut content = String::new();
    let mut text_x = 4.0;
    if let Some(png) = &visible.image_png {
        let image = image::load_from_memory(png).map_err(|e| MergeError::Image {
            name: "signature".into(),
            message: e.to_string(),
        })?;
        let rgba = image.to_rgba8();
        let (iw, ih) = rgba.dimensions();
        let mut rgb = Vec::with_capacity((iw * ih * 3) as usize);
        let mut alpha = Vec::with_capacity((iw * ih) as usize);
        for px in rgba.pixels() {
            rgb.extend_from_slice(&px.0[..3]);
            alpha.push(px[3]);
        }
        let mut mask = Stream::new(
            dictionary! { "Type" => "XObject", "Subtype" => "Image", "Width" => iw as i64, "Height" => ih as i64, "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8 },
            alpha,
        );
        let _ = mask.compress();
        let mask_id = doc.add_object(mask);
        let mut img = Stream::new(
            dictionary! { "Type" => "XObject", "Subtype" => "Image", "Width" => iw as i64, "Height" => ih as i64, "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "SMask" => mask_id },
            rgb,
        );
        let _ = img.compress();
        let img_id = doc.add_object(img);
        resources.set("XObject", dictionary! { "SigImg" => img_id });
        // Image occupies the left 55% of the box, fitted and centred.
        let area_w = w * 0.55 - 6.0;
        let area_h = h - 6.0;
        let scale = (area_w / iw as f64).min(area_h / ih as f64);
        let (dw, dh) = (iw as f64 * scale, ih as f64 * scale);
        let (dx, dy) = (3.0 + (area_w - dw) / 2.0, 3.0 + (area_h - dh) / 2.0);
        content.push_str(&format!(
            "q {dw:.3} 0 0 {dh:.3} {dx:.3} {dy:.3} cm /SigImg Do Q\n"
        ));
        text_x = w * 0.55 + 2.0;
    }
    let text_w = (w - text_x - 3.0).max(10.0);
    let mut lines = vec![
        "Digitally signed by".to_string(),
        signer.info.common_name.clone(),
        format!(
            "Date: {}",
            certs::format_time(now_secs)
                .trim_end_matches(" UTC")
                .to_string()
                + "Z"
        ),
    ];
    if let Some(reason) = options.reason.as_deref().filter(|r| !r.trim().is_empty()) {
        lines.push(format!("Reason: {}", reason.trim()));
    }
    // Fit the text to the box: the row height and the longest line both cap the size.
    let longest = lines.iter().map(|l| l.chars().count()).max().unwrap_or(1) as f64;
    let by_height = (h / (lines.len() as f64 + 1.0)) * 0.8;
    let by_width = text_w / (longest.max(6.0) * 0.52);
    let font_size = by_height.min(by_width).clamp(3.0, 11.0);
    let max_chars = ((text_w / (font_size * 0.5)) as usize).max(6);
    content.push_str("BT 0 0 0 rg /Helv ");
    content.push_str(&format!(
        "{font_size:.2} Tf {:.2} TL {text_x:.2} {:.2} Td\n",
        font_size * 1.2,
        h - font_size - 3.0
    ));
    for (i, line) in lines.iter().enumerate() {
        let clipped: String = line.chars().take(max_chars).collect();
        let escaped = clipped
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)");
        let ascii: String = escaped
            .chars()
            .map(|c| if c.is_ascii() { c } else { '?' })
            .collect();
        if i > 0 {
            content.push_str("T* ");
        }
        content.push_str(&format!("({ascii}) Tj\n"));
    }
    content.push_str("ET\n");
    let stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), w.into(), h.into()],
            "Resources" => resources,
        },
        content.into_bytes(),
    );
    Ok(doc.add_object(stream))
}

/// CMS SignedData (detached) over `digest`, with the signer's certificate embedded.
///
/// Built by hand from the `cms` types: one SignerInfo with contentType, signingTime and
/// messageDigest as signed attributes, signed with SHA-256 and the identity's key.
fn build_cms(signer: &Signer, digest: &[u8], now_secs: u64) -> Result<Vec<u8>, String> {
    use cms::content_info::CmsVersion;
    use cms::signed_data::{CertificateSet, SignerInfo, SignerInfos};
    use signature::{SignatureEncoding, Signer as _};

    fn e(what: &'static str) -> impl Fn(der::Error) -> String {
        move |err| format!("{what}: {err}")
    }
    let sha256 = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    };

    // Signed attributes (a SET, so the encoder orders them canonically).
    let attr = |oid: const_oid::ObjectIdentifier, value: Any| -> Result<Attribute, String> {
        let mut values: SetOfVec<Any> = SetOfVec::new();
        values.insert(value).map_err(e("attribute"))?;
        Ok(Attribute { oid, values })
    };
    let mut signed_attrs: SetOfVec<Attribute> = SetOfVec::new();
    signed_attrs
        .insert(attr(
            const_oid::db::rfc5911::ID_CONTENT_TYPE,
            Any::encode_from(&const_oid::db::rfc5911::ID_DATA).map_err(e("contentType"))?,
        )?)
        .map_err(e("attributes"))?;
    let signing_time = UtcTime::from_unix_duration(std::time::Duration::from_secs(now_secs))
        .map_err(e("signingTime"))?;
    signed_attrs
        .insert(attr(
            const_oid::db::rfc5911::ID_SIGNING_TIME,
            Any::encode_from(&signing_time).map_err(e("signingTime"))?,
        )?)
        .map_err(e("attributes"))?;
    let md = OctetString::new(digest).map_err(e("messageDigest"))?;
    signed_attrs
        .insert(attr(
            const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
            Any::encode_from(&md).map_err(e("messageDigest"))?,
        )?)
        .map_err(e("attributes"))?;

    // The signature is over the DER of the attributes as a SET (tag 0x31).
    let attrs_der = signed_attrs.to_der().map_err(e("attributes"))?;
    let (signature_bytes, signature_algorithm) = match &signer.key {
        PrivateKey::P256(k) => {
            let sig: p256::ecdsa::DerSignature = k
                .try_sign(&attrs_der)
                .map_err(|err| format!("signing: {err}"))?;
            (
                sig.to_bytes().to_vec(),
                AlgorithmIdentifierOwned {
                    oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                    parameters: None,
                },
            )
        }
        PrivateKey::Rsa(k) => {
            let sig: rsa::pkcs1v15::Signature = k
                .try_sign(&attrs_der)
                .map_err(|err| format!("signing: {err}"))?;
            (
                sig.to_vec(),
                AlgorithmIdentifierOwned {
                    oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
                    parameters: Some(Any::null()),
                },
            )
        }
    };

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: signer.certificate.tbs_certificate().issuer().clone(),
            serial_number: signer.certificate.tbs_certificate().serial_number().clone(),
        }),
        digest_alg: sha256.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm,
        signature: OctetString::new(signature_bytes).map_err(e("signature"))?,
        unsigned_attrs: None,
    };

    let mut digest_algorithms: SetOfVec<AlgorithmIdentifierOwned> = SetOfVec::new();
    digest_algorithms
        .insert(sha256)
        .map_err(e("digest algorithms"))?;
    let mut cert_set: SetOfVec<CertificateChoices> = SetOfVec::new();
    cert_set
        .insert(CertificateChoices::Certificate(signer.certificate.clone()))
        .map_err(e("certificates"))?;
    let mut infos: SetOfVec<SignerInfo> = SetOfVec::new();
    infos.insert(signer_info).map_err(e("signer infos"))?;
    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: content,
        certificates: Some(CertificateSet(cert_set)),
        crls: None,
        signer_infos: SignerInfos(infos),
    };
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).map_err(e("signed data"))?,
    };
    content_info.to_der().map_err(e("content info"))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SignatureReport {
    pub field: String,
    pub sub_filter: String,
    pub signer: Option<CertInfo>,
    /// The signer's certificate (PEM) so it can be added to a trust store.
    pub signer_certificate_pem: Option<String>,
    pub signing_time: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    /// The bytes the signature covers are unchanged.
    pub integrity_ok: bool,
    /// The signature's own cryptographic check passed.
    pub signature_ok: bool,
    /// Covers the whole file: nothing was appended after this signature.
    pub covers_whole_file: bool,
    pub trusted: bool,
    pub certificate_valid_now: bool,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub signatures: Vec<SignatureReport>,
    pub all_valid: bool,
    /// True when bytes were added after the last signature (e.g. edits or more signatures).
    pub modified_after_last_signature: bool,
}

/// Verify every signature in the file. `anchors` decides what counts as trusted.
pub fn verify_pdf(input: &MergeInput, anchors: &[Certificate]) -> Result<VerifyReport, MergeError> {
    let data: &[u8] = &input.data;
    let (doc, _) = merge::load_pdf(input)?;
    let mut reports = Vec::new();

    // Signature fields: any widget/field with /FT /Sig and a /V dictionary.
    let mut seen = std::collections::BTreeSet::new();
    for (id, object) in &doc.objects {
        let Ok(dict) = object.as_dict() else { continue };
        let is_sig_field = dict
            .get(b"FT")
            .and_then(Object::as_name)
            .map(|n| n == b"Sig")
            .unwrap_or(false);
        if !is_sig_field {
            continue;
        }
        let Ok(value_id) = dict.get(b"V").and_then(Object::as_reference) else {
            continue;
        };
        if !seen.insert(value_id) {
            continue;
        }
        let Ok(sig) = doc.get_dictionary(value_id) else {
            continue;
        };
        let field = dict
            .get(b"T")
            .ok()
            .and_then(|t| t.as_str().ok())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_else(|| format!("field {}", id.0));
        reports.push(verify_one(data, &field, sig, anchors));
    }
    reports.sort_by_key(|r| r.field.clone());
    // Only the last signature can cover the whole file; earlier ones never do.
    let modified = !reports.is_empty() && reports.iter().all(|r| !r.covers_whole_file);
    let all_valid = !reports.is_empty() && reports.iter().all(|r| r.integrity_ok && r.signature_ok);
    Ok(VerifyReport {
        signatures: reports,
        all_valid,
        modified_after_last_signature: modified,
    })
}

fn pdf_string(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    let bytes = dict.get(key).ok()?.as_str().ok()?;
    Some(decode_pdf_text(bytes))
}

fn decode_pdf_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn verify_one(
    data: &[u8],
    field: &str,
    sig: &lopdf::Dictionary,
    anchors: &[Certificate],
) -> SignatureReport {
    let mut report = SignatureReport {
        field: field.to_string(),
        sub_filter: sig
            .get(b"SubFilter")
            .and_then(Object::as_name)
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .unwrap_or_default(),
        signer: None,
        signer_certificate_pem: None,
        signing_time: pdf_string(sig, b"M").map(|m| pdf_date_to_display(&m)),
        reason: pdf_string(sig, b"Reason"),
        location: pdf_string(sig, b"Location"),
        contact: pdf_string(sig, b"ContactInfo"),
        digest_algorithm: String::new(),
        signature_algorithm: String::new(),
        integrity_ok: false,
        signature_ok: false,
        covers_whole_file: false,
        trusted: false,
        certificate_valid_now: false,
        problems: Vec::new(),
    };

    // ByteRange and Contents.
    let ranges: Vec<usize> = sig
        .get(b"ByteRange")
        .ok()
        .and_then(|o| o.as_array().ok())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_i64().ok())
                .map(|v| v.max(0) as usize)
                .collect()
        })
        .unwrap_or_default();
    let Ok(contents) = sig.get(b"Contents").and_then(|c| c.as_str()) else {
        report.problems.push("signature has no contents".into());
        return report;
    };
    if ranges.len() != 4
        || ranges[0] + ranges[1] > data.len()
        || ranges[2] + ranges[3] > data.len()
        || ranges[2] < ranges[0] + ranges[1]
    {
        report.problems.push("byte range is malformed".into());
        return report;
    }
    // The gap between the two ranges must be exactly the /Contents hex string.
    let gap = &data[ranges[0] + ranges[1]..ranges[2]];
    let gap_ok = gap.first() == Some(&b'<') && gap.last() == Some(&b'>');
    if !gap_ok || ranges[0] != 0 {
        report
            .problems
            .push("byte range does not bracket the signature as required".into());
    }
    report.covers_whole_file = ranges[2] + ranges[3] == data.len();

    let mut hasher = Sha256::new();
    hasher.update(&data[ranges[0]..ranges[0] + ranges[1]]);
    hasher.update(&data[ranges[2]..ranges[2] + ranges[3]]);
    let digest = hasher.finalize();

    // Parse CMS.
    let trimmed = trim_trailing_zeros(contents);
    let content_info = match ContentInfo::from_der(trimmed) {
        Ok(ci) => ci,
        Err(e) => {
            report
                .problems
                .push(format!("signature is not valid CMS: {e}"));
            return report;
        }
    };
    let signed_data = match content_info
        .content
        .to_der()
        .ok()
        .and_then(|d| SignedData::from_der(&d).ok())
    {
        Some(sd) => sd,
        None => {
            report
                .problems
                .push("signature is not CMS SignedData".into());
            return report;
        }
    };
    let Some(signer_info) = signed_data.signer_infos.0.iter().next() else {
        report.problems.push("no signer info".into());
        return report;
    };
    report.digest_algorithm = oid_name(&signer_info.digest_alg.oid);
    report.signature_algorithm = oid_name(&signer_info.signature_algorithm.oid);

    // Find the signer certificate.
    let certs: Vec<Certificate> = signed_data
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(cert) => Some(cert.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let cert = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => certs
            .iter()
            .find(|c| {
                *c.tbs_certificate().issuer() == isn.issuer
                    && *c.tbs_certificate().serial_number() == isn.serial_number
            })
            .or_else(|| certs.first()),
        SignerIdentifier::SubjectKeyIdentifier(_) => certs.first(),
    };
    let Some(cert) = cert else {
        report
            .problems
            .push("the signer's certificate is not embedded".into());
        return report;
    };
    let info = certs::cert_info(cert);
    report.certificate_valid_now = info.valid_now;
    report.trusted = certs::is_trusted(cert, anchors);
    report.signer = Some(info);
    report.signer_certificate_pem = cert.to_pem(der::pem::LineEnding::LF).ok();

    if signer_info.digest_alg.oid != const_oid::db::rfc5912::ID_SHA_256 {
        report.problems.push(format!(
            "unsupported digest algorithm {}",
            report.digest_algorithm
        ));
        return report;
    }

    // Signed attributes: messageDigest must equal our digest, and the signature is over the
    // DER of the attribute SET.
    let Some(signed_attrs) = &signer_info.signed_attrs else {
        report.problems.push("no signed attributes".into());
        return report;
    };
    let message_digest = signed_attrs
        .iter()
        .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
        .and_then(|a| a.values.iter().next())
        .and_then(|v| OctetString::from_der(&v.to_der().ok()?).ok())
        .map(|o| o.as_bytes().to_vec());
    match message_digest {
        Some(md) if md.as_slice() == digest.as_slice() => report.integrity_ok = true,
        Some(_) => report
            .problems
            .push("the document was changed after it was signed".into()),
        None => report
            .problems
            .push("signature carries no message digest".into()),
    }
    if let Some(st) = signed_attrs
        .iter()
        .find(|a| a.oid == const_oid::db::rfc5911::ID_SIGNING_TIME)
    {
        if let Some(v) = st.values.iter().next() {
            if let Ok(der_bytes) = v.to_der() {
                if let Ok(t) = UtcTime::from_der(&der_bytes) {
                    report.signing_time = Some(certs::format_time(t.to_unix_duration().as_secs()));
                }
            }
        }
    }
    let Ok(attrs_der) = signed_attrs.to_der() else {
        report
            .problems
            .push("signed attributes cannot be encoded".into());
        return report;
    };
    // Explicit [0] IMPLICIT tagging is replaced by the SET tag for the signature computation.
    let mut set_der = attrs_der;
    if !set_der.is_empty() {
        set_der[0] = 0x31; // SET OF
    }
    let sig_alg = normalise_signature_oid(
        &signer_info.signature_algorithm.oid,
        &cert
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid,
    );
    report.signature_ok = certs::verify_signature(
        cert.tbs_certificate().subject_public_key_info(),
        &sig_alg,
        &set_der,
        signer_info.signature.as_bytes(),
    );
    if !report.signature_ok {
        report
            .problems
            .push("the cryptographic signature does not verify".into());
    }
    if !report.trusted {
        report
            .problems
            .push("the signer's certificate is not in your trust list".into());
    }
    if !report.certificate_valid_now {
        report
            .problems
            .push("the signer's certificate is expired or not yet valid".into());
    }
    report
}

/// CMS often names the bare key algorithm (rsaEncryption / id-ecPublicKey) as the signature
/// algorithm; map that to the concrete SHA-256 variant we can check.
fn normalise_signature_oid(
    sig: &const_oid::ObjectIdentifier,
    key: &const_oid::ObjectIdentifier,
) -> const_oid::ObjectIdentifier {
    use const_oid::db::rfc5912::*;
    if *sig == RSA_ENCRYPTION
        || (*key == RSA_ENCRYPTION
            && *sig != SHA_256_WITH_RSA_ENCRYPTION
            && *sig != ID_EC_PUBLIC_KEY)
    {
        return SHA_256_WITH_RSA_ENCRYPTION;
    }
    if *sig == ID_EC_PUBLIC_KEY || *key == ID_EC_PUBLIC_KEY {
        return ECDSA_WITH_SHA_256;
    }
    *sig
}

fn oid_name(oid: &const_oid::ObjectIdentifier) -> String {
    use const_oid::db::rfc5912::*;
    if *oid == ID_SHA_256 {
        "SHA-256".into()
    } else if *oid == ID_SHA_1 {
        "SHA-1".into()
    } else if *oid == ID_SHA_384 {
        "SHA-384".into()
    } else if *oid == ID_SHA_512 {
        "SHA-512".into()
    } else if *oid == ECDSA_WITH_SHA_256 || *oid == ID_EC_PUBLIC_KEY {
        "ECDSA".into()
    } else if *oid == SHA_256_WITH_RSA_ENCRYPTION || *oid == RSA_ENCRYPTION {
        "RSA".into()
    } else {
        oid.to_string()
    }
}

fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == 0 {
        end -= 1;
    }
    &bytes[..end]
}

/// `D:20240131120000Z` -> `2024-01-31 12:00:00 UTC` (best effort).
fn pdf_date_to_display(m: &str) -> String {
    let s = m.trim_start_matches("D:");
    if s.len() >= 14 && s[..14].chars().all(|c| c.is_ascii_digit()) {
        format!(
            "{}-{}-{} {}:{}:{} {}",
            &s[..4],
            &s[4..6],
            &s[6..8],
            &s[8..10],
            &s[10..12],
            &s[12..14],
            if s[14..].starts_with('Z') || s.len() == 14 {
                "UTC"
            } else {
                &s[14..]
            }
        )
    } else {
        m.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::Store;
    use crate::merge::tests::sample_pdf;

    fn store_with_identity() -> (Store, String) {
        let dir = std::env::temp_dir().join(format!("cfm-pades-{}", rand::random::<u64>()));
        let store = Store::open(dir).unwrap();
        let info = store
            .create(
                "Ana Signer",
                Some("ana@example.org"),
                None,
                None,
                "pw123",
                30,
            )
            .unwrap();
        (store, info.id)
    }

    fn png_square() -> Vec<u8> {
        let img = image::ImageBuffer::from_fn(40, 20, |_, _| image::Rgba([0u8, 0, 0, 255]));
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    #[test]
    fn signs_and_verifies_with_visible_appearance() {
        let (store, id) = store_with_identity();
        let signer = store.unlock(&id, "pw123").unwrap();
        let input = MergeInput::new("doc.pdf", sample_pdf(2, "Doc"));
        let options = SignOptions {
            reason: Some("Approved".into()),
            location: Some("Berlin".into()),
            contact: None,
            visible: Some(VisibleSignature {
                placement: Placement {
                    page: 2,
                    image: 0,
                    cx: 0.7,
                    cy: 0.85,
                    width: 0.3,
                    height: 0.1,
                    angle: 0.0,
                },
                image_png: Some(png_square()),
            }),
        };
        let signed = sign_pdf(&input, &signer, &options).unwrap();
        assert!(signed.len() > input.data.len());
        assert!(
            signed.starts_with(&input.data),
            "signing must be an incremental update"
        );

        let report = verify_pdf(
            &MergeInput::new("doc.pdf", signed.clone()),
            &store.trust_anchors(),
        )
        .unwrap();
        assert_eq!(report.signatures.len(), 1, "{report:?}");
        let s = &report.signatures[0];
        assert!(s.integrity_ok, "{:?}", s.problems);
        assert!(s.signature_ok, "{:?}", s.problems);
        assert!(s.covers_whole_file && s.trusted && s.certificate_valid_now);
        assert_eq!(s.signer.as_ref().unwrap().common_name, "Ana Signer");
        assert_eq!(s.reason.as_deref(), Some("Approved"));
        assert!(s.signing_time.is_some());
        assert!(report.all_valid && !report.modified_after_last_signature);

        // The visible widget landed on page 2 with an appearance, and the page still renders.
        let doc = Document::load_mem(&signed).unwrap();
        let pages = doc.get_pages();
        let page2 = doc.get_dictionary(pages[&2]).unwrap();
        let annots = page2.get(b"Annots").unwrap().as_array().unwrap();
        assert_eq!(annots.len(), 1);
        let widget = doc
            .get_dictionary(annots[0].as_reference().unwrap())
            .unwrap();
        assert!(widget.has(b"AP"));
        assert_eq!(
            crate::preview::render_pdf_page_images(signed.clone(), 1, 1, 200).len(),
            1
        );
    }

    #[test]
    fn tampering_is_detected_and_untrusted_signers_are_flagged() {
        let (store, id) = store_with_identity();
        let signer = store.unlock(&id, "pw123").unwrap();
        let input = MergeInput::new("doc.pdf", sample_pdf(1, "Doc"));
        let signed = sign_pdf(&input, &signer, &SignOptions::default()).unwrap();

        // Flip a byte inside the original content.
        let mut tampered = signed.clone();
        let pos = find_from(&tampered, 0, b"Doc 1").unwrap();
        tampered[pos] = b'X';
        let report = verify_pdf(
            &MergeInput::new("doc.pdf", tampered.clone()),
            &store.trust_anchors(),
        )
        .unwrap();
        assert!(!report.signatures[0].integrity_ok);
        assert!(!report.all_valid);

        // Someone else verifying without our certificate: valid but untrusted.
        let report = verify_pdf(&MergeInput::new("doc.pdf", signed.clone()), &[]).unwrap();
        let s = &report.signatures[0];
        assert!(s.integrity_ok && s.signature_ok && !s.trusted);
        assert!(s.problems.iter().any(|p| p.contains("trust")));
    }

    #[test]
    fn two_signers_in_sequence_keep_both_signatures_valid() {
        let (store_a, a) = store_with_identity();
        let (store_b, b) = store_with_identity();
        let first = sign_pdf(
            &MergeInput::new("d.pdf", sample_pdf(1, "D")),
            &store_a.unlock(&a, "pw123").unwrap(),
            &SignOptions::default(),
        )
        .unwrap();
        let second = sign_pdf(
            &MergeInput::new("d.pdf", first.clone()),
            &store_b.unlock(&b, "pw123").unwrap(),
            &SignOptions::default(),
        )
        .unwrap();
        let mut anchors = store_a.trust_anchors();
        anchors.extend(store_b.trust_anchors());
        let report = verify_pdf(&MergeInput::new("d.pdf", second.clone()), &anchors).unwrap();
        assert_eq!(report.signatures.len(), 2);
        assert!(
            report
                .signatures
                .iter()
                .all(|s| s.integrity_ok && s.signature_ok && s.trusted),
            "{report:?}"
        );
        assert!(report.all_valid);
        // The first signature no longer covers the whole file (the second was appended),
        // but nothing was changed after the last signature.
        assert!(!report.signatures[0].covers_whole_file);
        assert!(report.signatures[1].covers_whole_file);
        assert!(!report.modified_after_last_signature);
        assert_eq!(
            report
                .signatures
                .iter()
                .filter(|s| s.covers_whole_file)
                .count(),
            1
        );
    }

    #[test]
    fn signs_owner_locked_pdfs_by_rewriting_them_unencrypted() {
        let (store, id) = store_with_identity();
        let locked = include_bytes!("../tests/fixtures/owner_locked.pdf");
        let signed = sign_pdf(
            &MergeInput::new("l.pdf", locked.to_vec()),
            &store.unlock(&id, "pw123").unwrap(),
            &SignOptions::default(),
        )
        .unwrap();
        let report = verify_pdf(
            &MergeInput::new("l.pdf", signed.clone()),
            &store.trust_anchors(),
        )
        .unwrap();
        assert!(report.all_valid, "{report:?}");
        assert!(Document::load_mem(&signed)
            .unwrap()
            .trailer
            .get(b"Encrypt")
            .is_err());
    }

    #[test]
    fn unsigned_document_reports_no_signatures() {
        let report = verify_pdf(&MergeInput::new("p.pdf", sample_pdf(1, "P")), &[]).unwrap();
        assert!(report.signatures.is_empty() && !report.all_valid);
    }
}
