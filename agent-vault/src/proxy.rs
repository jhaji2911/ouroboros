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
use bytes::Bytes;
use http::{Method, Uri};
use hyper::{
    body::HttpBody, service::Service, Body, Client, Request, Response, Server,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::task::{Context as TaskContext, Poll};
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

    // Extract the Host header
    let mut host = String::new();
    for line in &lines[1..] {
        if line.to_lowercase().starts_with("host:") {
            host = line.split(':').nth(1).unwrap_or("").trim().to_string();
            break;
        }
    }

    if host.is_empty() {
        log::warn!("Request from {} missing Host header", peer_addr);
        return Ok(());
    }

    log::debug!("{} {}{} -> {}", method_str, host, path, peer_addr);

    // Reconstruct headers with token rewriting
    let mut headers_rewritten = String::new();
    let mut body_start = 0;
    let mut found_blank_line = false;

    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            found_blank_line = true;
            body_start = i + 1;
            break;
        }
        // Rewrite token in headers
        let rewritten = rewrite_token(line);
        headers_rewritten.push_str(&rewritten);
        headers_rewritten.push('\n');
    }

    headers_rewritten.push('\n');

    // Extract and rewrite body
    let mut body_bytes = buffer[buffer.len().saturating_sub(2000)..].to_vec();
    let body_str = String::from_utf8_lossy(&body_bytes);
    let body_rewritten = rewrite_token(&body_str);

    // Reconstruct the HTTP request with rewritten token
    let request_line = format!("{} {} HTTP/1.1\r\n", method_str, path);
    let host_header = format!("host: {}\r\n", host);

    let mut request_to_send = format!("{}{}", request_line, host_header);
    request_to_send.push_str(&headers_rewritten);
    if !body_str.is_empty() {
        request_to_send.push_str(&body_rewritten);
    }

    log::info!(
        "Intercepted {} request to {} (token rewritten: {} → {})",
        method_str,
        host,
        DUMMY_TOKEN,
        REAL_TOKEN
    );

    // Forward to upstream server
    let upstream_addr = format!("{}:80", host);
    let mut upstream = tokio::net::TcpStream::connect(&upstream_addr).await
        .context(format!("Failed to connect to upstream {}", upstream_addr))?;

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
// Banner
// ---------------------------------------------------------------------------

fn println_banner_proxy() {
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    println!("{cyan}{bold}");
    println!(r"        ____....----````----....____ ");
    println!(r"   .--``                            ``--. ");
    println!(r" /`   .--.        orouboros           .--.`\ ");
    println!(r"|   /  _  \                          /  _  \ |");
    println!(r"|  | (@) | |    HTTP proxy mode       | (@) |  |");
    println!(r"|   \  ‾  /     credential vault      \  ‾  / |");
    println!(r" \   `--`    ________________________   `--`  /");
    println!(r"  `>  _     /     ↕ localhost:8888     \    _ <`");
    println!(r"   | / \   /  [FAKE]⇄[REAL] rewrites   \  / \ |");
    println!(r"   |/ ~~\/  HTTP headers & bodies       \/~~ \|");
    println!(r"   (  o  )                              (  o  )");
    println!(r"    \___/ `>___________________________<` \___/");
    println!(r"           ════════════════════════════       ");
    println!("{reset}");

    println!(
        "{bold}  a g e n t - v a u l t{reset}  {dim}proxy mode — v{}{reset}",
        env!("CARGO_PKG_VERSION")
    );
    println!("{dim}  HTTP/1.1 Credential Rewriter (macOS/Windows){reset}");
    println!();
}
