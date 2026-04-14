//! HTTP proxy mode for agent-vault (macOS, Windows, or any non-Linux platform).
//!
//! Runs a local transparent proxy on localhost:8888 that intercepts HTTP requests,
//! rewrites the dummy token with the real credential, and forwards to the upstream server.
//!
//! # Usage
//! ```bash
//! export HTTP_PROXY=http://localhost:8888
//! export HTTPS_PROXY=http://localhost:8888
//! ./agent-vault --mode proxy
//! ```

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// Token configuration — matches the eBPF mode
const DUMMY_TOKEN: &str = "FAKE_TOKEN_12345";
const REAL_TOKEN: &str = "REAL_SECRET_9999";
const PROXY_LISTEN: &str = "127.0.0.1:8888";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run_proxy_mode() -> Result<()> {
    println!();
    println_banner_proxy();

    let addr: SocketAddr = PROXY_LISTEN.parse()
        .context("Invalid proxy listen address")?;

    let listener = TcpListener::bind(&addr).await
        .context("Failed to bind TCP listener")?;

    log::info!("HTTP proxy listening on http://{}", PROXY_LISTEN);
    println!("{}  Proxy ready on http://{}", "✔", PROXY_LISTEN);
    println!();
    println!("  {}Export these environment variables in your agent's shell:{}", "\x1b[2m", "\x1b[0m");
    println!("  export HTTP_PROXY=http://localhost:8888");
    println!("  export HTTPS_PROXY=http://localhost:8888");
    println!("  export NO_PROXY=localhost,127.0.0.1");
    println!();
    println!("  {}All requests passing through the proxy will be rewritten:{}", "\x1b[2m", "\x1b[0m");
    println!("  {} → {}", DUMMY_TOKEN, REAL_TOKEN);
    println!();
    println!("  {}Press Ctrl-C to stop.{}", "\x1b[33m", "\x1b[0m");
    println!();

    // Accept incoming connections
    loop {
        let (socket, peer_addr) = listener.accept().await
            .context("Failed to accept connection")?;

        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(socket, peer_addr).await {
                log::warn!("Error handling connection from {}: {}", peer_addr, e);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// HTTP connection handler (transparent HTTP proxy)
// ---------------------------------------------------------------------------

async fn handle_http_connection(
    mut socket: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<()> {
    // Read the HTTP request line
    let mut buffer = vec![0; 4096];
    let n = socket.read(&mut buffer).await?;

    if n == 0 {
        return Ok(()); // client closed connection
    }

    buffer.truncate(n);

    // Parse the HTTP request manually (simple HTTP/1.1 requests only)
    let request_str = String::from_utf8_lossy(&buffer);

    // Extract method, path, and host
    let lines: Vec<&str> = request_str.lines().collect();
    if lines.is_empty() {
        return Ok(());
    }

    let first_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
    if first_line_parts.len() < 3 {
        return Ok(());
    }

    let method_str = first_line_parts[0];
    let path = first_line_parts[1];

    // Extract the Host header, preserving any explicit port (e.g. host:8080).
    let mut host = String::new();
    for line in &lines[1..] {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.to_lowercase().starts_with("host:") {
            host = trimmed["host:".len()..].trim().to_string();
            break;
        }
    }

    if host.is_empty() {
        log::warn!("Request from {} missing Host header", peer_addr);
        return Ok(());
    }

    log::debug!("{} {}{} -> {}", method_str, host, path, peer_addr);

    // Reconstruct headers, skipping the request line (index 0) and the Host
    // header (added explicitly below so it appears exactly once).
    // Use CRLF line endings as required by HTTP/1.1 (RFC 9112 §2.2).
    let mut headers_rewritten = String::new();
    for line in lines.iter().skip(1) {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            break; // blank line marks end of headers
        }
        if trimmed.to_lowercase().starts_with("host:") {
            continue; // omit; we add the canonical Host header below
        }
        headers_rewritten.push_str(&rewrite_token(trimmed));
        headers_rewritten.push_str("\r\n");
    }

    // Extract the body: everything after the first \r\n\r\n in the raw buffer.
    let body_bytes = find_body_slice(&buffer);
    let body_str = String::from_utf8_lossy(body_bytes);
    let body_rewritten = rewrite_token(&body_str);

    // Reconstruct the HTTP request with rewritten token.
    // Format: request-line CRLF Host CRLF other-headers CRLF blank-line body
    let request_line = format!("{} {} HTTP/1.1\r\n", method_str, path);
    let host_header  = format!("Host: {}\r\n", host);

    let mut request_to_send = String::new();
    request_to_send.push_str(&request_line);
    request_to_send.push_str(&host_header);
    request_to_send.push_str(&headers_rewritten);
    request_to_send.push_str("\r\n"); // blank line between headers and body
    request_to_send.push_str(&body_rewritten);

    log::info!(
        "Intercepted {} request to {} (token rewritten: {} → {})",
        method_str,
        host,
        DUMMY_TOKEN,
        REAL_TOKEN
    );

    // Forward to upstream server.
    // If the Host header already contains a port, use it; otherwise default to 80.
    let upstream_addr = if host.contains(':') {
        host.clone()
    } else {
        format!("{}:80", host)
    };
    let mut upstream = tokio::net::TcpStream::connect(&upstream_addr).await
        .with_context(|| format!("Failed to connect to upstream {upstream_addr}"))?;

    upstream.write_all(request_to_send.as_bytes()).await?;
    upstream.flush().await?;

    // Read response from upstream and send to client
    let mut response_buffer = vec![0; 16384];
    loop {
        match upstream.read(&mut response_buffer).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                socket.write_all(&response_buffer[..n]).await?;
                socket.flush().await?;
            }
            Err(e) => {
                log::warn!("Error reading from upstream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Token rewriting
// ---------------------------------------------------------------------------

/// Rewrite DUMMY_TOKEN with REAL_TOKEN in a string (headers or body).
fn rewrite_token(input: &str) -> String {
    input.replace(DUMMY_TOKEN, REAL_TOKEN)
}

// ---------------------------------------------------------------------------
// Body extraction
// ---------------------------------------------------------------------------

/// Return a slice of `buffer` starting after the first `\r\n\r\n` sequence,
/// which separates HTTP headers from the body.  Returns an empty slice if no
/// separator is found (header-only request).
fn find_body_slice(buffer: &[u8]) -> &[u8] {
    let len = buffer.len();
    for i in 0..len.saturating_sub(3) {
        if buffer[i..i + 4] == [b'\r', b'\n', b'\r', b'\n'] {
            return &buffer[i + 4..];
        }
    }
    &buffer[len..] // empty slice — no body
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn println_banner_proxy() {
    let cyan   = "\x1b[36m";
    let bold   = "\x1b[1m";
    let dim    = "\x1b[2m";
    let reset  = "\x1b[0m";

    println!();
    println!("{cyan}{bold}");
    println!(r"          ≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋");
    println!(r"         ≋                                      ≋");
    println!(r"        ≋    ╔══════════════════════════════╗    ≋");
    println!(r"        ≋    ║  ⊙  o u r o u b o r o s  ⊙  ║    ≋");
    println!(r"        ≋    ║    a g e n t - v a u l t    ║    ≋");
    println!(r"        ≋    ║    HTTP proxy  ·  port 8888  ║    ≋");
    println!(r"        ≋    ║    [FAKE] ─────────► [REAL]  ║    ≋");
    println!(r"        ≋    ╚══════════════════════════════╝    ≋");
    println!(r"         ≋                                      ≋");
    println!(r"          ≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋");
    println!(r"   >≋─────────── TAIL · BODY · HEAD ────────────≋◄(@)");
    println!(r"         ╰──── mouth closes the ring (ouroboros) ─╯");
    println!("{reset}");

    println!(
        "{bold}  agent-vault{reset}  {dim}v{}  ·  proxy mode{reset}",
        env!("CARGO_PKG_VERSION")
    );
    println!("{dim}  HTTP/1.1 Credential Rewriter (macOS / Windows / Linux){reset}");
    println!();
}
