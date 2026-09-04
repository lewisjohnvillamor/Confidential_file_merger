# Confidential File Merger

> **Do not upload your bank statements, contracts, IDs, tax returns, or medical records
> to random "free PDF merge" websites.** You have no idea who runs them, where your files
> go, how long they are kept, or who they are sold to. Merging a PDF does not need the
> internet. This tool does the same job on your own machine, with the browser itself
> blocked from talking to anyone else, so there is nobody you have to trust.

Merge PDFs and images into a single PDF, **fully offline**, on a machine you control.
One small Rust binary serves a drag-and-drop web GUI on `localhost`. Nothing is uploaded
to anyone, nothing phones home, nothing is logged about your documents.

- **Zero third parties.** Files are processed in memory by the local process and handed
  straight back to your browser. The page ships a strict Content-Security-Policy so the
  browser itself refuses to talk to any origin other than the local server.
- **PDF + images together.** PDF, PNG, JPEG, GIF, BMP, WebP and TIFF, in any mix and order.
  JPEGs are embedded byte-for-byte (no re-encoding); other images are stored losslessly.
- **Unlimited.** No file count, size, or "merges per day" limits. Merge, tweak the list,
  merge again. Feed the result back into the list and keep going.
- **Folders.** Drop a folder onto the page, pick one with the folder button, or (opt-in)
  point the server at a folder on its own disk. Files sort naturally (`scan1, scan2, scan10`).
- **Keeps what matters.** Page sizes, rotation, links and annotations survive. PDFs that
  only have an *owner* password (common with bank statements) open transparently; PDFs that
  need a *user* password are rejected with a clear message instead of producing garbage.
- **Also a CLI.** The same binary merges from the terminal for scripts and cron jobs.

![Screenshot of the merge queue](docs/screenshot-light.png)

## Quick start

You need a Rust toolchain (1.85 or newer, <https://rustup.rs>). No other dependencies,
no system libraries, no JavaScript build step.

```sh
git clone https://github.com/lewisjohnvillamor/Confidential_file_merger.git
cd Confidential_file_merger
cargo build --release
./target/release/confidential_file_merger
```

Then open <http://127.0.0.1:8080/> in a browser. That's it. The binary is self-contained;
copy it anywhere and run it.

```text
Confidential File Merger v0.1.0
  GUI:            http://127.0.0.1:8080/
  Local folders:  disabled (pass --allow-local-folders to enable)
  Upload limit:   unlimited
  Network:        none. Files are processed in memory and never leave this machine.
```

## Using the GUI

1. Drop files or folders onto the page, or use **Add files** / **Add a folder**.
2. Arrange the list: drag rows, use the arrow buttons, **Sort A→Z**, or **Reverse**.
   The list order is the page order.
3. Choose how images are placed (match image size, A4, or US Letter with optional margin)
   and the output file name.
4. **Merge to PDF**. The result downloads through your browser. The list stays, so you
   can adjust and merge again, or press **Add result to list** to chain merges.

## Server options

```text
confidential_file_merger [OPTIONS] [COMMAND]

Options:
  --host <HOST>                  Address to listen on [default: 127.0.0.1]
  --port <PORT>                  Port to listen on [default: 8080]
  --allow-local-folders          Let the GUI read folders from the *server's* disk by path
  --folder-root <DIR>            With --allow-local-folders, only allow paths under DIR
  --max-upload-mb <MB>           Cap the total upload size per merge (0 = unlimited)
```

Every option can also be set with an environment variable: `CFM_HOST`, `CFM_PORT`,
`CFM_ALLOW_LOCAL_FOLDERS`, `CFM_FOLDER_ROOT`, `CFM_MAX_UPLOAD_MB`.

### Merging folders from the server's disk

When the browser and the server run on the same machine (or the files are simply too big
to push through a browser upload), start with:

```sh
confidential_file_merger --allow-local-folders --folder-root ~/Documents
```

A **Merge a folder from this server's disk** section appears in the GUI. Type a path,
optionally include sub-folders, and **Scan & add**. The server reads those files directly.
This is off by default because it lets anyone who can reach the GUI read files the process
can read. Always pair it with `--folder-root` if the server is reachable by others.

### Hosting for a household or team

Bind to a LAN interface and keep the folder feature off unless you need it:

```sh
confidential_file_merger --host 0.0.0.0 --port 8080
```

Or with Docker:

```sh
docker build -t confidential-file-merger .
docker run --rm -p 8080:8080 confidential-file-merger
```

The container needs no outbound network. Put it behind your usual reverse proxy with TLS if
it is reachable beyond your own machine; the app itself deliberately does not include
authentication, so treat network reachability as the access control.

## Command line

```sh
# Files and folders, in order. Folders are scanned in natural sort order.
confidential_file_merger merge -o bundle.pdf cover.pdf scans/ appendix.png

# Recurse into sub-folders, place images on A4 with a 1/2 inch margin.
confidential_file_merger merge -r --page-size a4 --margin 36 -o all.pdf ./inbox
```

Exit code is non-zero with a one-line reason if any input cannot be used.

## How it works

- **PDFs** are parsed with [`lopdf`](https://crates.io/crates/lopdf), a pure-Rust PDF
  library. Pages are re-parented into a fresh page tree; attributes inherited from the
  original tree (media box, crop box, rotation, resources) are copied down first so nothing
  is lost. Unreachable objects from the source documents are pruned.
- **Images** are decoded with the [`image`](https://crates.io/crates/image) crate and
  embedded as PDF image XObjects. JPEG data is passed through untouched (DCTDecode);
  everything else becomes 8-bit Gray or RGB with Flate compression. Transparency is
  composited onto white.
- **Web server** is [`axum`](https://crates.io/crates/axum). The GUI is a single HTML file
  compiled into the binary; it loads no external fonts, scripts, or styles.

## Privacy checklist

| Concern | Answer |
| --- | --- |
| Are files uploaded anywhere? | Only to the server you started, over the address you chose. Default is `127.0.0.1`, unreachable from other machines. |
| Does the page load anything remote? | No. CSP `connect-src 'self'` makes the browser block it even if a bug tried. |
| Are files written to disk? | No. Merging happens in memory. Downloads are written by *your* browser. |
| Is anything logged? | One line per merge with the number of inputs and byte sizes. Never file names or content. |
| Telemetry, analytics, update checks? | None. |

The only outbound links in the GUI are the license text, the source repository and the
donation link in the footer, and those open only when you click them.

## Development

```sh
cargo test            # unit tests, including encrypted-PDF regression fixtures
cargo run -- --port 8080 --allow-local-folders --folder-root .
```

Test fixtures under `tests/fixtures/` are tiny PDFs with AES-256 encryption written by a
third-party tool, used to make sure owner-only encryption is opened and user-password
encryption is refused.

## Support the project

If this saved you from uploading a confidential document to a random website, consider
buying the author a coffee: <https://buymeacoffee.com/lewisjohnvil>

## License

Copyright 2026 Lewis John Villamor.

Licensed under the [Apache License, Version 2.0](LICENSE).
