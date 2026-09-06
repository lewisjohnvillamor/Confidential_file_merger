//! Confidential File Merger: an offline, self-hosted PDF + image merger.
//!
//! `confidential_file_merger` starts the local web GUI.
//! `confidential_file_merger merge -o out.pdf a.pdf 'b.pdf?pages=1-3' some_folder/` merges from the CLI.

mod images;
mod merge;
mod pagespec;
mod preview;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use merge::{MergeError, MergeInput, MergeOptions, Metadata, PageSize};
use preview::Thumbs;

const INDEX_HTML: &str = include_str!("../static/index.html");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const SESSION_COOKIE: &str = "cfm_session";
const JOB_TTL: Duration = Duration::from_secs(15 * 60);

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
    /// Merge files and folders from the command line, no browser needed.
    Merge(MergeArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum LogFormat {
    Text,
    Json,
}

#[derive(clap::Args, Debug)]
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

    /// Require this shared secret to use the GUI/API (entered once in the browser).
    #[arg(long, env = "CFM_ACCESS_TOKEN", hide_env_values = true)]
    access_token: Option<String>,

    /// Serve HTTPS with this PEM certificate (chain) file. Requires --tls-key.
    #[arg(long, env = "CFM_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for --tls-cert.
    #[arg(long, env = "CFM_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Serve HTTPS with a certificate generated at startup (browsers will warn once).
    #[arg(long, env = "CFM_TLS_SELF_SIGNED", conflicts_with = "tls_cert")]
    tls_self_signed: bool,

    /// How many merges may run at the same time; further requests wait in line.
    #[arg(long, default_value_t = 2, env = "CFM_MAX_CONCURRENT_MERGES", value_parser = clap::value_parser!(u16).range(1..))]
    max_concurrent_merges: u16,

    /// Log line format.
    #[arg(long, value_enum, default_value_t = LogFormat::Text, env = "CFM_LOG_FORMAT")]
    log_format: LogFormat,

    /// Open the GUI in the default browser once the server is listening.
    #[arg(long)]
    open: bool,
}

#[derive(clap::Args, Debug)]
struct MergeArgs {
    /// Output PDF path.
    #[arg(short, long)]
    output: PathBuf,

    /// Page size used for image inputs.
    #[arg(long, value_enum, default_value_t = PageSize::Fit)]
    page_size: PageSize,

    /// Margin (points) around images on A4/Letter pages.
    #[arg(long, default_value_t = 0.0)]
    margin: f64,

    /// Files and/or folders to merge, in order. Folders are scanned (sorted naturally).
    /// A file may carry options: `scan.pdf?pages=1-3,odd&rotate=90&rotate2=180&password=x`.
    #[arg(required = true)]
    inputs: Vec<String>,

    /// Recurse into sub-folders.
    #[arg(short, long)]
    recursive: bool,

    /// Password to try for every encrypted PDF (per-file `?password=` wins).
    #[arg(long)]
    password: Option<String>,

    /// Do not add one bookmark per input file.
    #[arg(long)]
    no_bookmarks: bool,

    /// Drop the source PDFs' own outlines instead of nesting them.
    #[arg(long)]
    no_source_outlines: bool,

    /// Do not merge interactive form fields.
    #[arg(long)]
    no_forms: bool,

    /// Skip de-duplication and compression of streams.
    #[arg(long)]
    no_optimize: bool,

    /// Ignore the DPI declared by images (1 pixel = 1 point).
    #[arg(long)]
    ignore_image_dpi: bool,

    /// Document title.
    #[arg(long)]
    title: Option<String>,
    /// Document author.
    #[arg(long)]
    author: Option<String>,
    /// Document subject.
    #[arg(long)]
    subject: Option<String>,
    /// Document keywords.
    #[arg(long)]
    keywords: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Merge(args)) => run_merge_cli(args),
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
    for arg in &args.inputs {
        let (path, spec) = pagespec::parse_input_arg(arg)?;
        let path = PathBuf::from(path);
        if path.is_dir() {
            for file in scan_folder(&path, args.recursive)? {
                let mut input = read_input(&file)?;
                input.password = args.password.clone();
                inputs.push(input);
            }
        } else {
            let mut input = read_input(&path)?;
            input.page_spec = spec.pages;
            input.rotate = spec.rotate;
            input.page_rotations = spec.page_rotations;
            input.password = spec.password.or_else(|| args.password.clone());
            inputs.push(input);
        }
    }
    let options = MergeOptions {
        page_size: args.page_size,
        margin_pt: args.margin,
        use_image_dpi: !args.ignore_image_dpi,
        bookmarks: !args.no_bookmarks,
        keep_outlines: !args.no_source_outlines,
        merge_forms: !args.no_forms,
        optimize: !args.no_optimize,
        metadata: Metadata {
            title: args.title,
            author: args.author,
            subject: args.subject,
            keywords: args.keywords,
        },
    };
    let pdf = merge::merge(&inputs, &options)?;
    std::fs::write(&args.output, &pdf)?;
    println!(
        "Merged {} file(s) into {} ({})",
        inputs.len(),
        args.output.display(),
        human_size(pdf.len())
    );
    Ok(())
}

fn read_input(path: &Path) -> std::io::Result<MergeInput> {
    Ok(MergeInput::new(
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        std::fs::read(path)?,
    ))
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
    access_token: Option<String>,
    secure_cookies: bool,
    merges: Semaphore,
    max_concurrent: usize,
    jobs: Mutex<HashMap<String, Job>>,
    log_json: bool,
}

struct Job {
    state: JobState,
    created: Instant,
    output_name: String,
}

enum JobState {
    Queued,
    Running {
        step: usize,
        total: usize,
        label: String,
    },
    Done {
        pdf: Vec<u8>,
    },
    Failed {
        message: String,
        code: &'static str,
    },
}

#[derive(Serialize)]
struct JobStatus {
    id: String,
    state: &'static str,
    step: usize,
    total: usize,
    label: String,
    error: Option<String>,
    code: Option<&'static str>,
    size: Option<usize>,
    output_name: String,
}

impl AppState {
    fn log(&self, event: &str, fields: &[(&str, String)]) {
        if self.log_json {
            let mut map = serde_json::Map::new();
            map.insert("event".into(), event.into());
            map.insert(
                "ts".into(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .into(),
            );
            for (k, v) in fields {
                map.insert((*k).into(), (*v).clone().into());
            }
            println!("{}", serde_json::Value::Object(map));
        } else {
            let rest: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("{event} {}", rest.join(" "));
        }
    }

    fn sweep_jobs(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        jobs.retain(|_, job| job.created.elapsed() < JOB_TTL);
    }
}

async fn serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let folder_root = match &args.folder_root {
        Some(root) => Some(
            std::fs::canonicalize(root)
                .map_err(|e| format!("--folder-root {}: {e}", root.display()))?,
        ),
        None => None,
    };
    let tls = args.tls_cert.is_some() || args.tls_self_signed;
    let state = Arc::new(AppState {
        allow_local_folders: args.allow_local_folders,
        folder_root,
        max_upload_mb: args.max_upload_mb,
        access_token: args.access_token.clone().filter(|t| !t.is_empty()),
        secure_cookies: tls,
        merges: Semaphore::new(args.max_concurrent_merges as usize),
        max_concurrent: args.max_concurrent_merges as usize,
        jobs: Mutex::new(HashMap::new()),
        log_json: args.log_format == LogFormat::Json,
    });

    let body_limit = if args.max_upload_mb == 0 {
        DefaultBodyLimit::disable()
    } else {
        DefaultBodyLimit::max((args.max_upload_mb as usize).saturating_mul(1024 * 1024))
    };

    let protected = Router::new()
        .route("/api/merge", post(merge_handler))
        .route("/api/jobs", post(job_create))
        .route("/api/jobs/:id", get(job_status).delete(job_delete))
        .route("/api/jobs/:id/result", get(job_result))
        .route("/api/inspect", post(inspect_handler))
        .route("/api/folder/scan", post(folder_scan))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ));

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/api/config", get(config))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .merge(protected)
        .layer(body_limit)
        .layer(middleware::from_fn(privacy_headers))
        .with_state(Arc::clone(&state));

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .map_err(|e| format!("invalid host/port: {e}"))?;

    let handle: axum_server::Handle<SocketAddr> = axum_server::Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            handle.graceful_shutdown(Some(Duration::from_secs(5)));
        });
    }
    {
        // Print the banner once we really are listening (port 0 resolves here too).
        let handle = handle.clone();
        let state = Arc::clone(&state);
        let open_browser = args.open;
        tokio::spawn(async move {
            if let Some(local) = handle.listening().await {
                let scheme = if tls { "https" } else { "http" };
                let shown = if local.ip().is_unspecified() {
                    format!("{scheme}://localhost:{}/", local.port())
                } else {
                    format!("{scheme}://{local}/")
                };
                print_banner(&state, &shown, tls);
                if open_browser {
                    if let Err(e) = open::that(&shown) {
                        eprintln!("could not open a browser: {e}");
                    }
                }
            }
        });
    }

    if tls {
        let (cert_pem, key_pem) = match (&args.tls_cert, &args.tls_key) {
            (Some(cert), Some(key)) => (std::fs::read(cert)?, std::fs::read(key)?),
            _ => {
                let mut names = vec!["localhost".to_string(), args.host.clone()];
                if let Ok(hostname) = std::env::var("HOSTNAME") {
                    names.push(hostname);
                }
                names.retain(|n| !n.is_empty() && n != "0.0.0.0" && n != "::");
                let generated = rcgen::generate_simple_self_signed(names)?;
                println!("Generated a self-signed certificate for this run; your browser will ask you to trust it once.");
                (
                    generated.cert.pem().into_bytes(),
                    generated.signing_key.serialize_pem().into_bytes(),
                )
            }
        };
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }
    Ok(())
}

fn print_banner(state: &AppState, url: &str, tls: bool) {
    if state.log_json {
        state.log(
            "server_start",
            &[("url", url.to_string()), ("version", VERSION.to_string())],
        );
        return;
    }
    println!("Confidential File Merger v{VERSION}");
    println!("  GUI:            {url}");
    println!(
        "  Access:         {}",
        if state.access_token.is_some() {
            "access token required"
        } else {
            "open to anyone who can reach this address"
        }
    );
    println!(
        "  TLS:            {}",
        if tls {
            "on"
        } else {
            "off (fine on localhost; use --tls-self-signed on a LAN)"
        }
    );
    println!(
        "  Local folders:  {}",
        if state.allow_local_folders {
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
        if state.max_upload_mb == 0 {
            "unlimited".to_string()
        } else {
            format!("{} MB", state.max_upload_mb)
        }
    );
    println!(
        "  Concurrency:    {} merge(s) at a time",
        state.max_concurrent
    );
    println!("  Network:        none. Files are processed in memory and never leave this machine.");
    println!("Press Ctrl+C to stop.");
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
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    response
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().find_map(|value| {
        value.to_str().ok()?.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    })
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (a.get(i).copied().unwrap_or(0) ^ b.get(i % b.len().max(1)).copied().unwrap_or(0))
            as usize;
    }
    diff == 0
}

fn is_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = &state.access_token else {
        return true;
    };
    if let Some(cookie) = cookie_value(headers, SESSION_COOKIE) {
        if constant_time_eq(&cookie, token) {
            return true;
        }
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| constant_time_eq(v.trim(), token))
        .unwrap_or(false)
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_authenticated(&state, request.headers()) {
        next.run(request).await
    } else {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Sign in with the access token first.",
            "unauthorized",
        )
        .into_response()
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    token: String,
}

async fn login(State(state): State<Arc<AppState>>, Json(req): Json<LoginRequest>) -> Response {
    let Some(token) = &state.access_token else {
        return StatusCode::NO_CONTENT.into_response();
    };
    if !constant_time_eq(req.token.trim(), token) {
        state.log("login_failed", &[]);
        return ApiError::new(
            StatusCode::UNAUTHORIZED,
            "That access token is not correct.",
            "unauthorized",
        )
        .into_response();
    }
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict{}",
        token,
        if state.secure_cookies { "; Secure" } else { "" }
    );
    ([(header::SET_COOKIE, cookie)], StatusCode::NO_CONTENT).into_response()
}

async fn logout(State(state): State<Arc<AppState>>) -> Response {
    let cookie = format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        if state.secure_cookies { "; Secure" } else { "" }
    );
    ([(header::SET_COOKIE, cookie)], StatusCode::NO_CONTENT).into_response()
}

// ---------------------------------------------------------------------------
// Basic routes
// ---------------------------------------------------------------------------

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": VERSION }))
}

#[derive(Serialize)]
struct ConfigResponse {
    version: &'static str,
    local_folders: bool,
    folder_root: Option<String>,
    max_upload_mb: u64,
    supported_extensions: &'static [&'static str],
    auth_required: bool,
    authenticated: bool,
    max_concurrent_merges: usize,
}

async fn config(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        version: VERSION,
        local_folders: state.allow_local_folders,
        folder_root: state.folder_root.as_ref().map(|p| p.display().to_string()),
        max_upload_mb: state.max_upload_mb,
        supported_extensions: merge::SUPPORTED_EXTENSIONS,
        auth_required: state.access_token.is_some(),
        authenticated: is_authenticated(&state, &headers),
        max_concurrent_merges: state.max_concurrent,
    })
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
    code: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>, code: &'static str) -> Self {
        ApiError {
            status,
            message: message.into(),
            code,
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::BAD_REQUEST, message, "invalid")
    }
    fn forbidden(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::FORBIDDEN, message, "forbidden")
    }
    fn from_merge(err: &MergeError) -> Self {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            err.to_string(),
            merge_error_code(err),
        )
    }
}

fn merge_error_code(err: &MergeError) -> &'static str {
    match err {
        MergeError::Encrypted { .. } => "encrypted",
        MergeError::WrongPassword { .. } => "wrong_password",
        MergeError::Unsupported { .. } => "unsupported",
        MergeError::PageSelection { .. } => "page_selection",
        MergeError::NoInputs => "no_inputs",
        _ => "invalid",
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message, "code": self.code })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Merge requests (shared by the synchronous endpoint and jobs)
// ---------------------------------------------------------------------------

/// Per-item settings sent by the GUI, matched by position to `file`/`path` fields.
#[derive(Deserialize, Default)]
struct ManifestItem {
    #[serde(default)]
    pages: Option<serde_json::Value>,
    #[serde(default)]
    rotate: i64,
    #[serde(default)]
    page_rotations: HashMap<String, i64>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Deserialize, Default)]
struct ManifestMetadata {
    title: Option<String>,
    author: Option<String>,
    subject: Option<String>,
    keywords: Option<String>,
}

#[derive(Deserialize, Default)]
struct Manifest {
    #[serde(default)]
    items: Vec<ManifestItem>,
    page_size: Option<String>,
    margin: Option<f64>,
    output_name: Option<String>,
    use_image_dpi: Option<bool>,
    bookmarks: Option<bool>,
    keep_outlines: Option<bool>,
    merge_forms: Option<bool>,
    optimize: Option<bool>,
    #[serde(default)]
    metadata: ManifestMetadata,
}

struct MergeRequest {
    inputs: Vec<MergeInput>,
    options: MergeOptions,
    output_name: String,
}

/// Multipart fields, in output order: `file` (upload) or `path` (server disk, opt-in).
/// Settings come either from a `manifest` JSON field or from plain `page_size`, `margin`,
/// `output_name`, `password` fields for curl users.
async fn parse_merge_form(
    state: &AppState,
    mut multipart: Multipart,
) -> Result<MergeRequest, ApiError> {
    let mut inputs: Vec<MergeInput> = Vec::new();
    let mut options = MergeOptions::default();
    let mut output_name = String::from("merged.pdf");
    let mut manifest: Option<Manifest> = None;
    let mut default_password: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Upload could not be read: {e}")))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                let name = field.file_name().unwrap_or("upload").to_string();
                let data = field.bytes().await.map_err(|e| {
                    ApiError::bad_request(format!("Upload of \"{name}\" failed: {e}"))
                })?;
                inputs.push(MergeInput::new(name, data.to_vec()));
            }
            "path" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                let path = resolve_local_path(state, raw.trim())?;
                inputs.push(read_input(&path).map_err(|e| {
                    ApiError::bad_request(format!("Could not read \"{}\": {e}", path.display()))
                })?);
            }
            "manifest" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                manifest = Some(
                    serde_json::from_str(&raw)
                        .map_err(|e| ApiError::bad_request(format!("Invalid manifest: {e}")))?,
                );
            }
            "page_size" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                options.page_size = PageSize::parse(&raw)
                    .ok_or_else(|| ApiError::bad_request(format!("Unknown page size \"{raw}\"")))?;
            }
            "margin" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                options.margin_pt = raw.trim().parse::<f64>().unwrap_or(0.0);
            }
            "output_name" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                output_name = sanitize_filename(&raw);
            }
            "password" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                default_password = Some(raw).filter(|p| !p.is_empty());
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    if let Some(m) = manifest {
        if let Some(ps) = m.page_size.as_deref() {
            options.page_size = PageSize::parse(ps)
                .ok_or_else(|| ApiError::bad_request(format!("Unknown page size \"{ps}\"")))?;
        }
        if let Some(margin) = m.margin {
            options.margin_pt = margin.max(0.0);
        }
        if let Some(name) = m.output_name.as_deref() {
            output_name = sanitize_filename(name);
        }
        options.use_image_dpi = m.use_image_dpi.unwrap_or(options.use_image_dpi);
        options.bookmarks = m.bookmarks.unwrap_or(options.bookmarks);
        options.keep_outlines = m.keep_outlines.unwrap_or(options.keep_outlines);
        options.merge_forms = m.merge_forms.unwrap_or(options.merge_forms);
        options.optimize = m.optimize.unwrap_or(options.optimize);
        options.metadata = Metadata {
            title: m.metadata.title,
            author: m.metadata.author,
            subject: m.metadata.subject,
            keywords: m.metadata.keywords,
        };
        for (input, item) in inputs.iter_mut().zip(m.items.iter()) {
            match &item.pages {
                Some(serde_json::Value::String(spec)) if !spec.trim().is_empty() => {
                    input.page_spec = Some(spec.clone())
                }
                Some(serde_json::Value::Array(list)) => {
                    let pages: Vec<u32> = list
                        .iter()
                        .filter_map(|v| v.as_u64())
                        .map(|v| v as u32)
                        .collect();
                    if !pages.is_empty() {
                        input.pages = Some(pages);
                    }
                }
                _ => {}
            }
            input.rotate = pagespec::normalize_rotation(item.rotate);
            for (page, deg) in &item.page_rotations {
                if let Ok(p) = page.parse::<u32>() {
                    input
                        .page_rotations
                        .insert(p, pagespec::normalize_rotation(*deg));
                }
            }
            input.password = item.password.clone().filter(|p| !p.is_empty());
        }
    }
    if let Some(pw) = default_password {
        for input in &mut inputs {
            if input.password.is_none() {
                input.password = Some(pw.clone());
            }
        }
    }
    Ok(MergeRequest {
        inputs,
        options,
        output_name,
    })
}

fn pdf_response(pdf: Vec<u8>, output_name: &str) -> Response {
    let ascii_name: String = output_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let disposition = format!(
        "attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{}",
        utf8_percent_encode(output_name, NON_ALPHANUMERIC)
    );
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pdf"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).unwrap_or_else(|_| {
                    HeaderValue::from_static("attachment; filename=\"merged.pdf\"")
                }),
            ),
        ],
        pdf,
    )
        .into_response()
}

/// POST /api/merge — synchronous: the response body is the PDF.
async fn merge_handler(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = parse_merge_form(&state, multipart).await?;
    let count = request.inputs.len();
    let total_bytes: usize = request.inputs.iter().map(|i| i.data.len()).sum();
    let _permit = state
        .merges
        .acquire()
        .await
        .map_err(|_| ApiError::bad_request("Server is shutting down."))?;
    let MergeRequest {
        inputs,
        options,
        output_name,
    } = request;
    let pdf = tokio::task::spawn_blocking(move || merge::merge(&inputs, &options))
        .await
        .map_err(|e| ApiError::bad_request(format!("Merge task failed: {e}")))?
        .map_err(|e| ApiError::from_merge(&e))?;
    state.log(
        "merge",
        &[
            ("inputs", count.to_string()),
            ("in", human_size(total_bytes)),
            ("out", human_size(pdf.len())),
        ],
    );
    Ok(pdf_response(pdf, &output_name))
}

// ---------------------------------------------------------------------------
// Jobs (asynchronous merges with progress)
// ---------------------------------------------------------------------------

fn new_job_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// POST /api/jobs — same form as /api/merge; returns the job status immediately.
async fn job_create(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> Result<Json<JobStatus>, ApiError> {
    state.sweep_jobs();
    let request = parse_merge_form(&state, multipart).await?;
    let id = new_job_id();
    let output_name = request.output_name.clone();
    {
        let mut jobs = state.jobs.lock().unwrap();
        jobs.insert(
            id.clone(),
            Job {
                state: JobState::Queued,
                created: Instant::now(),
                output_name,
            },
        );
    }
    let count = request.inputs.len();
    let total_bytes: usize = request.inputs.iter().map(|i| i.data.len()).sum();
    let worker_state = Arc::clone(&state);
    let job_id = id.clone();
    tokio::spawn(async move {
        let Ok(_permit) = worker_state.merges.acquire().await else {
            return;
        };
        {
            let mut jobs = worker_state.jobs.lock().unwrap();
            if let Some(job) = jobs.get_mut(&job_id) {
                job.state = JobState::Running {
                    step: 0,
                    total: count + 3,
                    label: "Starting".into(),
                };
            } else {
                return; // cancelled while queued
            }
        }
        let MergeRequest {
            inputs, options, ..
        } = request;
        let progress_state = Arc::clone(&worker_state);
        let progress_id = job_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            merge::merge_with_progress(&inputs, &options, |p| {
                let mut jobs = progress_state.jobs.lock().unwrap();
                if let Some(job) = jobs.get_mut(&progress_id) {
                    job.state = JobState::Running {
                        step: p.step,
                        total: p.total,
                        label: p.label,
                    };
                }
            })
        })
        .await;
        let mut jobs = worker_state.jobs.lock().unwrap();
        let Some(job) = jobs.get_mut(&job_id) else {
            return;
        };
        job.state = match result {
            Ok(Ok(pdf)) => {
                worker_state.log(
                    "merge",
                    &[
                        ("inputs", count.to_string()),
                        ("in", human_size(total_bytes)),
                        ("out", human_size(pdf.len())),
                    ],
                );
                JobState::Done { pdf }
            }
            Ok(Err(e)) => JobState::Failed {
                message: e.to_string(),
                code: merge_error_code(&e),
            },
            Err(e) => JobState::Failed {
                message: format!("Merge task failed: {e}"),
                code: "invalid",
            },
        };
    });
    Ok(Json(job_status_json(&id, &state).unwrap()))
}

fn job_status_json(id: &str, state: &AppState) -> Option<JobStatus> {
    let jobs = state.jobs.lock().unwrap();
    let job = jobs.get(id)?;
    let (st, step, total, label, error, code, size) = match &job.state {
        JobState::Queued => (
            "queued",
            0,
            0,
            "Waiting for a free slot".to_string(),
            None,
            None,
            None,
        ),
        JobState::Running { step, total, label } => {
            ("running", *step, *total, label.clone(), None, None, None)
        }
        JobState::Done { pdf } => (
            "done",
            1,
            1,
            "Done".to_string(),
            None,
            None,
            Some(pdf.len()),
        ),
        JobState::Failed { message, code } => (
            "error",
            0,
            0,
            "Failed".to_string(),
            Some(message.clone()),
            Some(*code),
            None,
        ),
    };
    Some(JobStatus {
        id: id.to_string(),
        state: st,
        step,
        total,
        label,
        error,
        code,
        size,
        output_name: job.output_name.clone(),
    })
}

async fn job_status(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<JobStatus>, ApiError> {
    job_status_json(&id, &state).map(Json).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "Unknown or expired job.",
            "not_found",
        )
    })
}

async fn job_delete(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> StatusCode {
    state.jobs.lock().unwrap().remove(&id);
    StatusCode::NO_CONTENT
}

/// GET /api/jobs/:id/result — the PDF; the job is forgotten once it has been fetched.
async fn job_result(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let mut jobs = state.jobs.lock().unwrap();
    let Some(job) = jobs.get(&id) else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Unknown or expired job.",
            "not_found",
        ));
    };
    match &job.state {
        JobState::Done { .. } => {
            let job = jobs.remove(&id).unwrap();
            let JobState::Done { pdf } = job.state else {
                unreachable!()
            };
            Ok(pdf_response(pdf, &job.output_name))
        }
        JobState::Failed { message, code } => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            message.clone(),
            code,
        )),
        _ => Err(ApiError::new(
            StatusCode::CONFLICT,
            "The merge is still running.",
            "running",
        )),
    }
}

// ---------------------------------------------------------------------------
// Inspect (page counts, thumbnails)
// ---------------------------------------------------------------------------

/// POST /api/inspect — multipart with one `file` (or `path`), optional `password`,
/// `thumbs` = none|first|all, `max_edge` in pixels, `max_pages` for `all`.
async fn inspect_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<preview::Inspection>, ApiError> {
    let mut input: Option<MergeInput> = None;
    let mut password: Option<String> = None;
    let mut thumbs = Thumbs::First;
    let mut max_edge: u32 = 160;
    let mut max_pages: usize = 400;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                let file_name = field.file_name().unwrap_or("upload").to_string();
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                input = Some(MergeInput::new(file_name, data.to_vec()));
            }
            "path" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                let path = resolve_local_path(&state, raw.trim())?;
                input = Some(read_input(&path).map_err(|e| ApiError::bad_request(e.to_string()))?);
            }
            "password" => {
                password = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| ApiError::bad_request(e.to_string()))?,
                )
                .filter(|p| !p.is_empty())
            }
            "thumbs" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                thumbs = match raw.trim() {
                    "none" => Thumbs::None,
                    "all" => Thumbs::All(max_pages),
                    _ => Thumbs::First,
                };
            }
            "max_edge" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                max_edge = raw.trim().parse::<u32>().unwrap_or(160).clamp(16, 1024);
            }
            "max_pages" => {
                let raw = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                max_pages = raw.trim().parse::<usize>().unwrap_or(400).clamp(1, 2000);
                if let Thumbs::All(_) = thumbs {
                    thumbs = Thumbs::All(max_pages);
                }
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }
    let input = input.ok_or_else(|| ApiError::bad_request("No file was provided."))?;
    let result = tokio::task::spawn_blocking(move || {
        preview::inspect(
            &input.name,
            &input.data,
            password.as_deref(),
            thumbs,
            max_edge,
        )
    })
    .await
    .map_err(|e| ApiError::bad_request(format!("Inspect task failed: {e}")))?
    .map_err(|e| ApiError::from_merge(&e))?;
    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Server-side folders
// ---------------------------------------------------------------------------

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
        return Err(ApiError::bad_request(format!(
            "\"{}\" is not a folder.",
            dir.display()
        )));
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
            let kind = if merge::extension(&name) == "pdf" {
                "pdf"
            } else {
                "image"
            };
            FolderEntry {
                name,
                path: p.display().to_string(),
                size,
                kind,
            }
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
        .filter(|c| {
            !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') && !c.is_control()
        })
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
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(token: Option<&str>) -> AppState {
        AppState {
            allow_local_folders: false,
            folder_root: None,
            max_upload_mb: 0,
            access_token: token.map(str::to_string),
            secure_cookies: false,
            merges: Semaphore::new(1),
            max_concurrent: 1,
            jobs: Mutex::new(HashMap::new()),
            log_json: false,
        }
    }

    #[test]
    fn natural_sort_orders_numbers_numerically() {
        let mut v = vec!["scan10.png", "Scan2.png", "scan1.png", "b.pdf", "a.pdf"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            v,
            vec!["a.pdf", "b.pdf", "scan1.png", "Scan2.png", "scan10.png"]
        );
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
        let closed = state(None);
        assert!(resolve_local_path(&closed, "/").is_err());
        let dir = std::env::temp_dir();
        let root = std::fs::canonicalize(&dir).unwrap();
        let mut scoped = state(None);
        scoped.allow_local_folders = true;
        scoped.folder_root = Some(root.clone());
        assert_eq!(
            resolve_local_path(&scoped, dir.to_str().unwrap()).unwrap(),
            root
        );
        assert!(resolve_local_path(&scoped, "/").is_err());
    }

    #[test]
    fn auth_accepts_cookie_or_bearer_only_with_the_right_token() {
        let open = state(None);
        assert!(is_authenticated(&open, &HeaderMap::new()));
        let locked = state(Some("s3cret"));
        assert!(!is_authenticated(&locked, &HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; cfm_session=s3cret"),
        );
        assert!(is_authenticated(&locked, &h));
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("cfm_session=s3cre"),
        );
        assert!(!is_authenticated(&locked, &h));
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cret"),
        );
        assert!(is_authenticated(&locked, &h));
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nope"),
        );
        assert!(!is_authenticated(&locked, &h));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }
}
