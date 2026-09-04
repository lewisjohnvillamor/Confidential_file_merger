//! Confidential File Merger: an offline, self-hosted PDF + image merger.
//!
//! `confidential_file_merger` (no subcommand) starts the local web GUI.
//! `confidential_file_merger merge -o out.pdf a.pdf b.png some_folder/` merges from the CLI.

mod merge;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

use merge::{MergeInput, MergeOptions, PageSize};

const INDEX_HTML: &str = include_str!("../static/index.html");
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "confidential_file_merger",
    version,
    about = "Fully offline PDF & image merger with a local web GUI. Nothing ever leaves your machine."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the local web GUI (default when no subcommand is given).
    Serve(ServeArgs),
    /// Merge files and folders from the command line, no browser needed.
    Merge(MergeArgs),
}

#[derive(clap::Args, Debug, Clone)]
struct ServeArgs {
    /// Address to listen on. Keep 127.0.0.1 unless you deliberately want LAN access.
    #[arg(long, default_value = "127.0.0.1", env = "CFM_HOST")]
    host: String,

    /// Port to listen on.
    #[arg(long, default_value_t = 8080, env = "CFM_PORT")]
    port: u16,

    /// Let the GUI read files from folders on the *server's* disk by path.
    /// Only enable when the browser and this program run on the same trusted machine.
    #[arg(long, env = "CFM_ALLOW_LOCAL_FOLDERS")]
    allow_local_folders: bool,

    /// When local folders are allowed, restrict them to this directory (and below).
    #[arg(long, env = "CFM_FOLDER_ROOT")]
    folder_root: Option<PathBuf>,

    /// Maximum total upload size per merge, in megabytes. 0 = unlimited.
    #[arg(long, default_value_t = 0, env = "CFM_MAX_UPLOAD_MB")]
    max_upload_mb: u64,
}

#[derive(clap::Args, Debug)]
struct MergeArgs {
    /// Output PDF path.
    #[arg(short, long)]
    output: PathBuf,

    /// Page size used for image inputs.
    #[arg(long, value_enum, default_value_t = PageSizeArg::Fit)]
    page_size: PageSizeArg,

    /// Margin (points) around images on A4/Letter pages.
    #[arg(long, default_value_t = 0.0)]
    margin: f64,

    /// Files and/or folders to merge, in order. Folders are scanned (sorted naturally).
    #[arg(required = true)]
    inputs: Vec<PathBuf>,

    /// Recurse into sub-folders.
    #[arg(short, long)]
    recursive: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum PageSizeArg {
    Fit,
    A4,
    Letter,
}

impl From<PageSizeArg> for PageSize {
    fn from(value: PageSizeArg) -> Self {
        match value {
            PageSizeArg::Fit => PageSize::Fit,
            PageSizeArg::A4 => PageSize::A4,
            PageSizeArg::Letter => PageSize::Letter,
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Merge(args)) => run_merge_cli(args),
        Some(Command::Serve(args)) => serve(args).await,
        None => serve(cli.serve).await,
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// CLI merge
// ---------------------------------------------------------------------------

fn run_merge_cli(args: MergeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut inputs = Vec::new();
    for path in &args.inputs {
        if path.is_dir() {
            for file in scan_folder(path, args.recursive)? {
                inputs.push(read_input(&file)?);
            }
        } else {
            inputs.push(read_input(path)?);
        }
    }
    let options = MergeOptions {
        page_size: args.page_size.into(),
        margin_pt: args.margin,
    };
    let pdf = merge::merge(&inputs, options)?;
    std::fs::write(&args.output, &pdf)?;
    println!(
        "Merged {} file(s) into {} ({} bytes)",
        inputs.len(),
        args.output.display(),
        pdf.len()
    );
    Ok(())
}

fn read_input(path: &Path) -> std::io::Result<MergeInput> {
    Ok(MergeInput {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        data: std::fs::read(path)?,
    })
}

/// List supported files in a folder, sorted the way a human would sort them (1, 2, 10).
fn scan_folder(dir: &Path, recursive: bool) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            if recursive {
                dirs.push(path);
            }
        } else if merge::is_supported_name(&name) {
            files.push(path);
        }
    }
    files.sort_by(|a, b| natural_cmp(&a.to_string_lossy(), &b.to_string_lossy()));
    dirs.sort_by(|a, b| natural_cmp(&a.to_string_lossy(), &b.to_string_lossy()));
    for sub in dirs {
        files.extend(scan_folder(&sub, true)?);
    }
    Ok(files)
}

/// Case-insensitive comparison that treats digit runs as numbers.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    let (mut ai, mut bi) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(ca), Some(cb)) if ca.is_ascii_digit() && cb.is_ascii_digit() => {
                let mut na = String::new();
                while let Some(c) = ai.peek().copied().filter(|c| c.is_ascii_digit()) {
                    na.push(c);
                    ai.next();
                }
                let mut nb = String::new();
                while let Some(c) = bi.peek().copied().filter(|c| c.is_ascii_digit()) {
                    nb.push(c);
                    bi.next();
                }
                let (ta, tb) = (na.trim_start_matches('0'), nb.trim_start_matches('0'));
                let ord = ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(ca), Some(cb)) => {
                if ca != cb {
                    return ca.cmp(&cb);
                }
                ai.next();
                bi.next();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Web server
// ---------------------------------------------------------------------------

struct AppState {
    allow_local_folders: bool,
    folder_root: Option<PathBuf>,
    max_upload_mb: u64,
}

async fn serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let folder_root = match &args.folder_root {
        Some(root) => Some(std::fs::canonicalize(root).map_err(|e| {
            format!("--folder-root {}: {e}", root.display())
        })?),
        None => None,
    };
    let state = Arc::new(AppState {
        allow_local_folders: args.allow_local_folders,
        folder_root,
        max_upload_mb: args.max_upload_mb,
    });

    let body_limit = if args.max_upload_mb == 0 {
        DefaultBodyLimit::disable()
    } else {
        DefaultBodyLimit::max((args.max_upload_mb as usize).saturating_mul(1024 * 1024))
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/config", get(config))
        .route("/api/merge", post(merge_handler))
        .route("/api/folder/scan", post(folder_scan))
        .layer(body_limit)
        .layer(middleware::from_fn(privacy_headers))
        .with_state(Arc::clone(&state));

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .map_err(|e| format!("invalid host/port: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    println!("Confidential File Merger v{VERSION}");
    println!("  GUI:            http://{local}/");
    println!(
        "  Local folders:  {}",
        if args.allow_local_folders {
            match &state.folder_root {
                Some(root) => format!("enabled, restricted to {}", root.display()),
                None => "enabled (any path readable by this process)".to_string(),
            }
        } else {
            "disabled (pass --allow-local-folders to enable)".to_string()
        }
    );
    println!(
        "  Upload limit:   {}",
        if args.max_upload_mb == 0 { "unlimited".to_string() } else { format!("{} MB", args.max_upload_mb) }
    );
    println!("  Network:        none. Files are processed in memory and never leave this machine.");
    println!("Press Ctrl+C to stop.");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// Headers that make the "nothing leaves this machine" promise enforceable by the browser:
/// the CSP forbids the page from contacting any origin other than this server.
async fn privacy_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; \
             img-src 'self' blob: data:; connect-src 'self'; form-action 'self'; \
             base-uri 'none'; object-src 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    response
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Serialize)]
struct ConfigResponse {
    version: &'static str,
    local_folders: bool,
    folder_root: Option<String>,
    max_upload_mb: u64,
    supported_extensions: &'static [&'static str],
}

async fn config(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        version: VERSION,
        local_folders: state.allow_local_folders,
        folder_root: state.folder_root.as_ref().map(|p| p.display().to_string()),
        max_upload_mb: state.max_upload_mb,
        supported_extensions: merge::SUPPORTED_EXTENSIONS,
    })
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        ApiError { status: StatusCode::BAD_REQUEST, message: message.into() }
    }
    fn forbidden(message: impl Into<String>) -> Self {
        ApiError { status: StatusCode::FORBIDDEN, message: message.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

/// POST /api/merge — multipart form.
///
/// Fields, in the order the output should have them:
///   * `file`       an uploaded PDF or image (repeatable)
///   * `path`       a path on the server's disk (repeatable, only with --allow-local-folders)
///
/// Plus optional settings: `page_size` (fit|a4|letter), `margin` (points), `output_name`.
async fn merge_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    let mut inputs: Vec<MergeInput> = Vec::new();
    let mut options = MergeOptions::default();
    let mut output_name = String::from("merged.pdf");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Upload could not be read: {e}")))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                let name = field.file_name().unwrap_or("upload").to_string();
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Upload of \"{name}\" failed: {e}")))?;
                inputs.push(MergeInput { name, data: data.to_vec() });
            }
            "path" => {
                let raw = field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?;
                let path = resolve_local_path(&state, raw.trim())?;
                inputs.push(read_input(&path).map_err(|e| {
                    ApiError::bad_request(format!("Could not read \"{}\": {e}", path.display()))
                })?);
            }
            "page_size" => {
                let raw = field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?;
                options.page_size = PageSize::parse(&raw)
                    .ok_or_else(|| ApiError::bad_request(format!("Unknown page size \"{raw}\"")))?;
            }
            "margin" => {
                let raw = field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?;
                options.margin_pt = raw.trim().parse::<f64>().unwrap_or(0.0);
            }
            "output_name" => {
                let raw = field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?;
                output_name = sanitize_filename(&raw);
            }
            _ => {
                // Unknown field: drain and ignore.
                let _ = field.bytes().await;
            }
        }
    }

    let count = inputs.len();
    let total_bytes: usize = inputs.iter().map(|i| i.data.len()).sum();
    let pdf = tokio::task::spawn_blocking(move || merge::merge(&inputs, options))
        .await
        .map_err(|e| ApiError::bad_request(format!("Merge task failed: {e}")))?
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    println!(
        "merged {count} input(s), {} in -> {} out",
        human_size(total_bytes),
        human_size(pdf.len())
    );

    let ascii_name: String = output_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') { c } else { '_' })
        .collect();
    let disposition = format!(
        "attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{}",
        utf8_percent_encode(&output_name, NON_ALPHANUMERIC)
    );

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/pdf")),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).unwrap_or_else(|_| {
                    HeaderValue::from_static("attachment; filename=\"merged.pdf\"")
                }),
            ),
        ],
        pdf,
    )
        .into_response())
}

#[derive(Deserialize)]
struct FolderScanRequest {
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Serialize)]
struct FolderEntry {
    name: String,
    path: String,
    size: u64,
    kind: &'static str,
}

/// POST /api/folder/scan — list supported files in a server-side folder.
async fn folder_scan(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FolderScanRequest>,
) -> Result<Json<Vec<FolderEntry>>, ApiError> {
    let dir = resolve_local_path(&state, req.path.trim())?;
    if !dir.is_dir() {
        return Err(ApiError::bad_request(format!("\"{}\" is not a folder.", dir.display())));
    }
    let files = scan_folder(&dir, req.recursive)
        .map_err(|e| ApiError::bad_request(format!("Could not read folder: {e}")))?;
    let entries = files
        .into_iter()
        .map(|p| {
            let name = p
                .strip_prefix(&dir)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_else(|_| p.display().to_string());
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let kind = if merge::extension(&name) == "pdf" { "pdf" } else { "image" };
            FolderEntry { name, path: p.display().to_string(), size, kind }
        })
        .collect();
    Ok(Json(entries))
}

fn resolve_local_path(state: &AppState, raw: &str) -> Result<PathBuf, ApiError> {
    if !state.allow_local_folders {
        return Err(ApiError::forbidden(
            "Reading folders from the server's disk is disabled. Start with --allow-local-folders to enable it.",
        ));
    }
    if raw.is_empty() {
        return Err(ApiError::bad_request("No path given."));
    }
    let expanded = expand_home(raw);
    let canonical = std::fs::canonicalize(&expanded)
        .map_err(|e| ApiError::bad_request(format!("\"{raw}\": {e}")))?;
    if let Some(root) = &state.folder_root {
        if !canonical.starts_with(root) {
            return Err(ApiError::forbidden(format!(
                "\"{raw}\" is outside the allowed folder root {}.",
                root.display()
            )));
        }
    }
    Ok(canonical)
}

fn expand_home(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

fn sanitize_filename(raw: &str) -> String {
    let mut name: String = raw
        .trim()
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') && !c.is_control())
        .collect();
    name = name.trim_matches(|c| c == '.' || c == ' ').to_string();
    if name.is_empty() {
        name = "merged".to_string();
    }
    if !name.to_ascii_lowercase().ends_with(".pdf") {
        name.push_str(".pdf");
    }
    name
}

fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural_sort_orders_numbers_numerically() {
        let mut v = vec!["scan10.png", "Scan2.png", "scan1.png", "b.pdf", "a.pdf"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(v, vec!["a.pdf", "b.pdf", "scan1.png", "Scan2.png", "scan10.png"]);
    }

    #[test]
    fn filenames_are_sanitized() {
        assert_eq!(sanitize_filename("  report "), "report.pdf");
        assert_eq!(sanitize_filename("../../etc/passwd"), "etcpasswd.pdf");
        assert_eq!(sanitize_filename(""), "merged.pdf");
        assert_eq!(sanitize_filename("Final.PDF"), "Final.PDF");
        assert_eq!(sanitize_filename("a:b*c.pdf"), "abc.pdf");
    }

    #[test]
    fn local_paths_require_opt_in_and_stay_under_root() {
        let closed = AppState { allow_local_folders: false, folder_root: None, max_upload_mb: 0 };
        assert!(resolve_local_path(&closed, "/").is_err());

        let dir = std::env::temp_dir();
        let root = std::fs::canonicalize(&dir).unwrap();
        let scoped = AppState { allow_local_folders: true, folder_root: Some(root.clone()), max_upload_mb: 0 };
        assert_eq!(resolve_local_path(&scoped, dir.to_str().unwrap()).unwrap(), root);
        assert!(resolve_local_path(&scoped, "/").is_err());
    }
}
