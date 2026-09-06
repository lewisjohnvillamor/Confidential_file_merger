//! Parsing of page selections ("1-3,5,8-"), rotations, and the `path?pages=..&rotate=..`
//! input syntax used by the CLI.

use std::collections::BTreeMap;

/// Parse a page selection into an ordered list of 1-based page numbers.
///
/// Accepts comma-separated terms: `N`, `N-M` (either direction), `N-` (to the end),
/// `-M` (from the start), `all`, `odd`, `even`, `last`. Whitespace is ignored.
pub fn parse_page_spec(spec: &str, total: u32) -> Result<Vec<u32>, String> {
    let spec = spec.trim();
    if total == 0 {
        return Err("the file has no pages".to_string());
    }
    if spec.is_empty() || spec.eq_ignore_ascii_case("all") {
        return Ok((1..=total).collect());
    }
    let mut pages = Vec::new();
    for raw in spec.split(',') {
        let term = raw.trim().to_ascii_lowercase();
        if term.is_empty() {
            continue;
        }
        match term.as_str() {
            "all" => pages.extend(1..=total),
            "odd" => pages.extend((1..=total).filter(|n| n % 2 == 1)),
            "even" => pages.extend((1..=total).filter(|n| n % 2 == 0)),
            "last" => pages.push(total),
            _ => {
                if let Some((a, b)) = term.split_once('-') {
                    let start = if a.trim().is_empty() {
                        1
                    } else {
                        parse_page(a, total)?
                    };
                    let end = if b.trim().is_empty() {
                        total
                    } else {
                        parse_page(b, total)?
                    };
                    if start <= end {
                        pages.extend(start..=end);
                    } else {
                        pages.extend((end..=start).rev());
                    }
                } else {
                    pages.push(parse_page(&term, total)?);
                }
            }
        }
    }
    if pages.is_empty() {
        return Err("the page selection is empty".to_string());
    }
    Ok(pages)
}

fn parse_page(s: &str, total: u32) -> Result<u32, String> {
    let s = s.trim();
    let n: u32 = if s == "last" {
        total
    } else {
        s.parse()
            .map_err(|_| format!("\"{s}\" is not a page number"))?
    };
    if n == 0 {
        return Err("page numbers start at 1".to_string());
    }
    if n > total {
        return Err(format!(
            "page {n} does not exist (the file has {total} page{})",
            if total == 1 { "" } else { "s" }
        ));
    }
    Ok(n)
}

/// Normalize a rotation in degrees to 0, 90, 180 or 270. Accepts negatives and multiples.
pub fn normalize_rotation(deg: i64) -> i32 {
    deg.rem_euclid(360) as i32
}

pub fn parse_rotation(s: &str) -> Result<i32, String> {
    let deg: i64 = s
        .trim()
        .trim_end_matches('°')
        .parse()
        .map_err(|_| format!("\"{s}\" is not a rotation in degrees"))?;
    let r = normalize_rotation(deg);
    if r % 90 != 0 {
        return Err("rotation must be a multiple of 90 degrees".to_string());
    }
    Ok(r)
}

/// Per-input options given on the command line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InputSpec {
    pub pages: Option<String>,
    pub rotate: i32,
    pub password: Option<String>,
    /// Per-page rotation overrides, e.g. `rotate=90` for all plus `rotate3=180` for page 3.
    pub page_rotations: BTreeMap<u32, i32>,
}

/// Split `path?pages=1-3&rotate=90&password=x` into the path and its options.
///
/// If the whole string names an existing file, it is taken verbatim so that files with a
/// literal `?` in their name still work.
pub fn parse_input_arg(arg: &str) -> Result<(String, InputSpec), String> {
    if std::path::Path::new(arg).exists() {
        return Ok((arg.to_string(), InputSpec::default()));
    }
    let Some((path, query)) = arg.rsplit_once('?') else {
        return Ok((arg.to_string(), InputSpec::default()));
    };
    if !query.contains('=') {
        return Ok((arg.to_string(), InputSpec::default()));
    }
    let mut spec = InputSpec::default();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(format!("\"{pair}\" is not a key=value option"));
        };
        let key = key.trim().to_ascii_lowercase();
        match key.as_str() {
            "pages" | "p" => spec.pages = Some(value.to_string()),
            "rotate" | "r" => spec.rotate = parse_rotation(value)?,
            "password" | "pw" => spec.password = Some(value.to_string()),
            k if k.starts_with("rotate") => {
                let page: u32 = k["rotate".len()..]
                    .parse()
                    .map_err(|_| format!("\"{k}\" is not a valid option (use rotateN=deg)"))?;
                spec.page_rotations.insert(page, parse_rotation(value)?);
            }
            _ => {
                return Err(format!(
                    "unknown option \"{key}\" (use pages, rotate, rotateN, password)"
                ))
            }
        }
    }
    Ok((path.to_string(), spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_keywords() {
        assert_eq!(parse_page_spec("1-3,5", 8).unwrap(), vec![1, 2, 3, 5]);
        assert_eq!(parse_page_spec("6-", 8).unwrap(), vec![6, 7, 8]);
        assert_eq!(parse_page_spec("-2", 8).unwrap(), vec![1, 2]);
        assert_eq!(parse_page_spec("3-1", 8).unwrap(), vec![3, 2, 1]);
        assert_eq!(parse_page_spec("odd", 5).unwrap(), vec![1, 3, 5]);
        assert_eq!(parse_page_spec("even, last", 5).unwrap(), vec![2, 4, 5]);
        assert_eq!(parse_page_spec("", 3).unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_page_spec("ALL", 2).unwrap(), vec![1, 2]);
    }

    #[test]
    fn rejects_bad_pages() {
        assert!(parse_page_spec("9", 8)
            .unwrap_err()
            .contains("does not exist"));
        assert!(parse_page_spec("0", 8).unwrap_err().contains("start at 1"));
        assert!(parse_page_spec("x", 8).is_err());
        assert!(parse_page_spec("1", 0).is_err());
    }

    #[test]
    fn rotations_normalize() {
        assert_eq!(parse_rotation("90").unwrap(), 90);
        assert_eq!(parse_rotation("-90").unwrap(), 270);
        assert_eq!(parse_rotation("450").unwrap(), 90);
        assert_eq!(parse_rotation("180°").unwrap(), 180);
        assert!(parse_rotation("45").is_err());
    }

    #[test]
    fn parses_input_args() {
        let (path, spec) =
            parse_input_arg("scan.pdf?pages=1-3,5&rotate=90&rotate2=180&pw=abc").unwrap();
        assert_eq!(path, "scan.pdf");
        assert_eq!(spec.pages.as_deref(), Some("1-3,5"));
        assert_eq!(spec.rotate, 90);
        assert_eq!(spec.page_rotations.get(&2), Some(&180));
        assert_eq!(spec.password.as_deref(), Some("abc"));
        let (path, spec) = parse_input_arg("plain.pdf").unwrap();
        assert_eq!(path, "plain.pdf");
        assert_eq!(spec, InputSpec::default());
        assert!(parse_input_arg("a.pdf?bogus=1").is_err());
    }
}
