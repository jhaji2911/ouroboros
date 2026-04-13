//! xtask — build automation for agent-vault
//!
//! Coordinates eBPF and daemon builds with proper toolchain management.
//!
//! # Usage
//! ```bash
//! cargo xtask build-ebpf --release
//! cargo xtask build --release
//! cargo xtask build-all --release
//! ```

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Enable release mode (optimizations)
    #[arg(short, long, global = true)]
    release: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF kernel-side program for bpfel-unknown-none target
    BuildEbpf,
    /// Build user-space agent-vault daemon
    Build,
    /// Build both eBPF and daemon in order
    BuildAll,
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::BuildEbpf => build_ebpf(args.release),
        Commands::Build => build_daemon(args.release),
        Commands::BuildAll => {
            build_ebpf(args.release)?;
            build_daemon(args.release)
        }
    }
}

// ---------------------------------------------------------------------------
// eBPF build (nightly + custom target)
// ---------------------------------------------------------------------------

fn build_ebpf(release: bool) -> Result<()> {
    println!("🛠️  Building eBPF program (agent-vault-ebpf)...");

    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly")
        .arg("build")
        .arg("--package")
        .arg("agent-vault-ebpf")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let output = cmd
        .output()
        .context("Failed to spawn cargo +nightly build for eBPF")?;

    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(anyhow!(
            "eBPF build failed. Ensure you have: rustup toolchain install nightly && rustup component add rust-src --toolchain nightly && cargo install bpf-linker"
        ));
    }

    let profile = if release { "release" } else { "debug" };
    let ebpf_path = format!("target/bpfel-unknown-none/{}/agent-vault-ebpf", profile);

    println!("✅ eBPF bytecode built: {}", ebpf_path);
    Ok(())
}

// ---------------------------------------------------------------------------
// Daemon build (stable)
// ---------------------------------------------------------------------------

fn build_daemon(release: bool) -> Result<()> {
    println!("🛠️  Building agent-vault daemon...");

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--package")
        .arg("agent-vault");

    if release {
        cmd.arg("--release");
    }

    let output = cmd
        .output()
        .context("Failed to spawn cargo build for agent-vault")?;

    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(anyhow!("Daemon build failed"));
    }

    let profile = if release { "release" } else { "debug" };
    let binary_path = format!("target/{}/agent-vault", profile);

    println!("✅ Daemon binary built: {}", binary_path);
    Ok(())
}
