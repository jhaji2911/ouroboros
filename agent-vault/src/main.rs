//! agent-vault — Zero-Knowledge credential injector daemon.
//!
//! Supports two modes:
//! - **ebpf mode** (Linux): kernel-space eBPF cgroup_skb/egress hook
//! - **proxy mode** (macOS/Windows): user-space HTTP/1.1 proxy on localhost:8888
//!
//! # Usage
//! ```bash
//! # Linux (auto-detect or explicit):
//! ./agent-vault --mode ebpf
//!
//! # macOS/Windows:
//! ./agent-vault --mode proxy
//! export HTTP_PROXY=http://localhost:8888
//! ```

#[cfg(target_os = "linux")]
mod ebpf;
mod proxy;

use anyhow::Result;
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(name = "agent-vault")]
#[command(about = "Zero-Knowledge Credential Injector", long_about = None)]
struct Args {
    /// Execution mode
    #[arg(
        short,
        long,
        value_name = "MODE",
        help = "Mode: 'ebpf' (Linux only) or 'proxy' (cross-platform)"
    )]
    #[arg(value_enum)]
    mode: Option<Mode>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    /// Kernel-space eBPF cgroup_skb/egress hook (Linux only)
    #[cfg(target_os = "linux")]
    Ebpf,
    /// User-space HTTP/1.1 proxy (macOS, Windows, Linux)
    Proxy,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Determine which mode to run
    #[cfg(target_os = "linux")]
    {
        let mode = match args.mode {
            Some(Mode::Ebpf) => Mode::Ebpf,
            Some(Mode::Proxy) => Mode::Proxy,
            None => Mode::Ebpf, // Default to eBPF on Linux
        };
        match mode {
            Mode::Ebpf => ebpf::run_ebpf_mode().await,
            Mode::Proxy => proxy::run_proxy_mode().await,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux platforms eBPF is unavailable; always run the proxy.
        let _ = args;
        proxy::run_proxy_mode().await
    }
}
